package releasepkg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	TagEpoch   int64
	HeadEpoch  int64
}

func inspectRepository(ctx context.Context, root, version string) (repositoryState, error) {
	git, err := exec.LookPath("git")
	if err != nil {
		return repositoryState{}, nil
	}
	out, err := runCombined(ctx, root, nil, git, "rev-parse", "--is-inside-work-tree")
	if err != nil || strings.TrimSpace(string(out)) != "true" {
		return repositoryState{}, nil
	}
	state := repositoryState{InWorkTree: true, TagEpoch: -1, HeadEpoch: -1}

	args := append([]string{"diff", "--name-only", "-z", "HEAD", "--"}, releaseSourcePaths...)
	tracked, err := runCombined(ctx, root, nil, git, args...)
	if err != nil {
		return repositoryState{}, fmt.Errorf("inspect tracked release changes: %w", err)
	}
	args = append([]string{"ls-files", "--others", "-z", "--"}, releaseSourcePaths...)
	untracked, err := runCombined(ctx, root, nil, git, args...)
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
	_, tagRefErr := runCombined(ctx, root, nil, git, "rev-parse", "-q", "--verify", tagRef)
	if tagRefErr == nil {
		tagType, typeErr := runCombined(ctx, root, nil, git, "cat-file", "-t", tagRef)
		if typeErr != nil || strings.TrimSpace(string(tagType)) != "tag" {
			return repositoryState{}, fmt.Errorf("release tag v%s must be an annotated tag", version)
		}
		tagCommit, peelErr := runCombined(ctx, root, nil, git, "rev-parse", "--verify", tagRef+"^{commit}")
		if peelErr != nil {
			return repositoryState{}, fmt.Errorf("release tag v%s must point to a commit: %w", version, peelErr)
		}
		headCommit, headErr := runCombined(ctx, root, nil, git, "rev-parse", "--verify", "HEAD^{commit}")
		if headErr != nil {
			return repositoryState{}, fmt.Errorf("resolve HEAD for release tag: %w", headErr)
		}
		if strings.TrimSpace(string(tagCommit)) != strings.TrimSpace(string(headCommit)) {
			return repositoryState{}, fmt.Errorf("release tag v%s does not point to HEAD", version)
		}
		state.TagExists = true
		state.TagEpoch, err = gitEpoch(ctx, root, git, "v"+version+"^{}")
		if err != nil {
			return repositoryState{}, err
		}
	} else {
		var exitErr *exec.ExitError
		if !errors.As(tagRefErr, &exitErr) || exitErr.ExitCode() != 1 {
			return repositoryState{}, fmt.Errorf("inspect release tag v%s: %w", version, tagRefErr)
		}
	}
	if headEpoch, headErr := gitEpoch(ctx, root, git, "HEAD"); headErr == nil {
		state.HeadEpoch = headEpoch
	}
	return state, nil
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

func gitEpoch(ctx context.Context, root, git, ref string) (int64, error) {
	out, err := runCombined(ctx, root, nil, git, "show", "-s", "--format=%ct", ref)
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
