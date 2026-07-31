package releasepkg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var releaseSourcePaths = []string{
	".env.example", "CHANGELOG.md", "LICENSE", "README.md", "README.en.md", "VERSION", "sun.sh",
	"docs",
	"files/needrestart-report-only.conf", "files/release-signing.pub.asc",
	"files/security-update-notify.logrotate", "files/security-update-notify.service",
	".github/workflows/ci.yml", ".github/workflows/mirror-release.yml",
	"cmd", "internal", "go.mod", "go.sum", "go.work", "go.work.sum", "vendor",
}

type repositoryState struct {
	InWorkTree bool
	Dirty      bool
	DirtyFiles []string
	TagExists  bool
	TagObject  string
	TagEpoch   int64
	HeadCommit string
	HeadEpoch  int64
}

func inspectRepository(ctx context.Context, root, version string) (repositoryState, error) {
	gitEnv := gitInspectionEnvironment()
	git, err := exec.LookPath("git")
	if err != nil {
		return outsideRepository(root, fmt.Errorf("locate git: %w", err))
	}
	out, err := runGitCombined(ctx, root, gitEnv, git, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		// A probe failure (dubious ownership, unreadable objects, ...) must not be reported as
		// "not a repository": that silently clears Dirty and TagExists, skipping both the
		// uncommitted-sources gate and the official-release signing escalation in Build.
		return outsideRepository(root, fmt.Errorf("inspect git work tree: %w", err))
	}
	if got := strings.TrimSpace(string(out)); got != "true" {
		if got == "false" {
			// A successful "false" is Git's bare-repository answer, not the
			// not-a-repository error accepted by outsideRepository below.
			return repositoryState{}, errors.New("git reports that the release root is not a work tree")
		}
		return repositoryState{}, fmt.Errorf("inspect git work tree: unexpected response %q", got)
	}
	top, err := runGitCombined(ctx, root, gitEnv, git, "rev-parse", "--show-toplevel")
	if err != nil {
		return repositoryState{}, fmt.Errorf("resolve git work tree root: %w", err)
	}
	sameRoot, err := sameDirectory(root, strings.TrimSpace(string(top)))
	if err != nil {
		return repositoryState{}, fmt.Errorf("validate git work tree root: %w", err)
	}
	if !sameRoot {
		// An extracted source tree can legitimately be placed below an unrelated
		// repository. Its parent's tags, commit time, and dirty state must not be
		// mistaken for release metadata belonging to this source root.
		return outsideRepository(root, errors.New("release root is nested inside a different git work tree"))
	}
	state := repositoryState{InWorkTree: true, TagEpoch: -1, HeadEpoch: -1}
	headCommit, err := runGitCombined(ctx, root, gitEnv, git, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return repositoryState{}, fmt.Errorf("resolve HEAD: %w", err)
	}
	state.HeadCommit = strings.TrimSpace(string(headCommit))

	args := append([]string{"diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", state.HeadCommit, "--"}, releaseSourcePaths...)
	tracked, err := runGitCombined(ctx, root, gitEnv, git, args...)
	if err != nil {
		return repositoryState{}, fmt.Errorf("inspect tracked release changes: %w", err)
	}
	args = append([]string{"ls-files", "--others", "-z", "--"}, releaseSourcePaths...)
	untracked, err := runGitCombined(ctx, root, gitEnv, git, args...)
	if err != nil {
		return repositoryState{}, fmt.Errorf("inspect untracked release sources: %w", err)
	}
	for _, output := range [][]byte{tracked, untracked} {
		for _, item := range bytes.Split(output, []byte{0}) {
			if len(item) != 0 {
				state.DirtyFiles = append(state.DirtyFiles, filepath.ToSlash(string(item)))
			}
		}
	}
	state.DirtyFiles = uniqueSorted(state.DirtyFiles)
	state.Dirty = len(state.DirtyFiles) != 0

	tagRef := "refs/tags/v" + version
	tagObject, tagExists, err := readOptionalGitRef(ctx, root, gitEnv, git, tagRef)
	if err != nil {
		return repositoryState{}, fmt.Errorf("inspect release tag v%s: %w", version, err)
	}
	if tagExists {
		tagType, typeErr := runGitCombined(ctx, root, gitEnv, git, "cat-file", "-t", tagObject)
		if typeErr != nil || strings.TrimSpace(string(tagType)) != "tag" {
			return repositoryState{}, fmt.Errorf("release tag v%s must be an annotated tag", version)
		}
		tagCommit, peelErr := runGitCombined(ctx, root, gitEnv, git, "rev-parse", "--verify", tagObject+"^{commit}")
		if peelErr != nil {
			return repositoryState{}, fmt.Errorf("release tag v%s must point to a commit: %w", version, peelErr)
		}
		if strings.TrimSpace(string(tagCommit)) != state.HeadCommit {
			return repositoryState{}, fmt.Errorf("release tag v%s does not point to HEAD", version)
		}
		state.TagExists = true
		state.TagObject = tagObject
		state.TagEpoch, err = gitEpoch(ctx, root, gitEnv, git, tagObject+"^{}")
		if err != nil {
			return repositoryState{}, err
		}
	}
	if headEpoch, headErr := gitEpoch(ctx, root, gitEnv, git, state.HeadCommit); headErr == nil {
		state.HeadEpoch = headEpoch
	}
	headAfter, headErr := runGitCombined(ctx, root, gitEnv, git, "rev-parse", "--verify", "HEAD^{commit}")
	if headErr != nil || strings.TrimSpace(string(headAfter)) != state.HeadCommit {
		return repositoryState{}, errors.New("repository HEAD changed while inspecting release sources")
	}
	tagAfter, tagExistsAfter, tagErr := readOptionalGitRef(ctx, root, gitEnv, git, tagRef)
	if tagErr != nil || tagExistsAfter != tagExists || tagAfter != tagObject {
		return repositoryState{}, errors.New("release tag changed while inspecting release sources")
	}
	return state, nil
}

func readOptionalGitRef(ctx context.Context, root string, env []string, git, ref string) (string, bool, error) {
	out, err := runGitCombined(ctx, root, env, git, "rev-parse", "-q", "--verify", ref)
	if err == nil {
		return strings.TrimSpace(string(out)), true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return "", false, nil
	}
	return "", false, err
}

func runGitCombined(ctx context.Context, root string, env []string, git string, args ...string) ([]byte, error) {
	// Repository-local fsmonitor commands and hooks are not part of source
	// inspection. Disable them so a read-only release preflight cannot execute
	// repository-configured helper programs.
	prefix := []string{"-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"}
	return runCombined(ctx, root, env, git, append(prefix, args...)...)
}

func gitInspectionEnvironment() []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if strings.HasPrefix(key, "GIT_") || key == "LC_ALL" || key == "LANG" || key == "LANGUAGE" {
			continue
		}
		env = append(env, item)
	}
	return append(env, "GIT_NO_REPLACE_OBJECTS=1", "LC_ALL=C")
}

func sameDirectory(left, right string) (bool, error) {
	leftInfo, err := os.Stat(left)
	if err != nil {
		return false, err
	}
	rightInfo, err := os.Stat(right)
	if err != nil {
		return false, err
	}
	return leftInfo.IsDir() && rightInfo.IsDir() && os.SameFile(leftInfo, rightInfo), nil
}

// outsideRepository accepts "there is no repository to inspect" only when root genuinely has no .git
// entry, which is the legitimate case of packaging an extracted source tree. When .git is present the
// probe failure is surfaced instead, so a repository that git refuses to read can never be mistaken
// for a non-repository and quietly bypass the release gates.
func outsideRepository(root string, cause error) (repositoryState, error) {
	if _, err := os.Lstat(filepath.Join(root, ".git")); err == nil {
		return repositoryState{}, cause
	} else if !errors.Is(err, fs.ErrNotExist) {
		return repositoryState{}, fmt.Errorf("inspect .git metadata: %w", err)
	}
	return repositoryState{}, nil
}

func resolveEpoch(ctx context.Context, root, version string, explicit *int64, repo repositoryState) (int64, error) {
	if explicit != nil {
		if *explicit < 0 {
			return 0, fmt.Errorf("source-date-epoch must not be negative")
		}
		return *explicit, nil
	}
	if repo.TagExists {
		return repo.TagEpoch, nil
	}
	if repo.InWorkTree && repo.HeadEpoch >= 0 {
		return repo.HeadEpoch, nil
	}
	return 0, fmt.Errorf("cannot determine SOURCE_DATE_EPOCH for %s; set it explicitly", version)
}

func gitEpoch(ctx context.Context, root string, env []string, git, ref string) (int64, error) {
	out, err := runGitCombined(ctx, root, env, git, "show", "-s", "--format=%ct", ref)
	if err != nil {
		return 0, fmt.Errorf("read git timestamp for %s: %w", ref, err)
	}
	epoch, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil || epoch < 0 {
		return 0, fmt.Errorf("invalid git timestamp for %s: %q", ref, strings.TrimSpace(string(out)))
	}
	return epoch, nil
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
