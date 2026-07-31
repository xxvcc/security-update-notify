package releasepkg

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/assets"
)

func TestMirrorWorkflowBindsVersionedBootstrapTrustSet(t *testing.T) {
	root := repositoryRoot(t)
	b, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "mirror-release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(b)
	for _, item := range []string{
		`workflows: ['CI']`,
		`environment: release-mirror`,
		`ref: ${{ github.workflow_sha }}`,
		`path: released-source`,
		`persist-credentials: false`,
		assets.ReleaseSigningFingerprint,
		`pin="$expected_pin"`,
		`"rel/$tarball" "$version" "$epoch" released-source`,
		`needs: verify-and-sync`,
		`uses: ./.github/workflows/live-canary.yml`,
		`BOOTSTRAP_VERSION_NOTATION`,
		`--known-notation`,
		`NOTATION_NAME`,
		`NOTATION_FLAGS`,
		`NOTATION_DATA`,
		`--show-notation`,
	} {
		if !strings.Contains(workflow, item) {
			t.Fatalf("mirror version-binding invariant missing: %s", item)
		}
	}
	if strings.Contains(workflow, "\n  release:\n") || strings.Contains(workflow, `python3 released-source/`) {
		t.Fatal("mirror workflow must treat the release tag only as data")
	}
	requiredInOrder := []string{
		`expected_assets+=("$bootstrap_signature_asset")`,
		`--verify "rel/$BOOTSTRAP_SIGNATURE_ASSET" "$verify_dir/sun.sh"`,
		`cmp files/release-signing.pub.asc "deploy/$TAG/release-signing.pub.asc"`,
		`assets+=("$BOOTSTRAP_SIGNATURE_ASSET" release-signing.pub.asc)`,
		`--verify "public-check/$BOOTSTRAP_SIGNATURE_ASSET" public-check/sun.sh`,
		`- name: Confirm GitHub Latest before stable update`,
		`latest_tag="$(gh api "repos/$GITHUB_REPOSITORY/releases/latest" --jq .tag_name)"`,
		`- name: Publish stable bootstrap through forced-command rrsync`,
		`"deploy/$TAG/sun.sh" "$MIRROR_USER@$MIRROR_HOST:sun.sh"`,
		`"$MIRROR_BASE_URL/sun.sh?run=$GITHUB_RUN_ID&attempt=$GITHUB_RUN_ATTEMPT"`,
		`cmp "deploy/$TAG/sun.sh" public-sun.sh`,
		`- name: Publish latest manifest last through forced-command rrsync`,
		`latest.json "$MIRROR_USER@$MIRROR_HOST:latest.json"`,
		`"$MIRROR_BASE_URL/latest.json?run=$GITHUB_RUN_ID&attempt=$GITHUB_RUN_ATTEMPT"`,
		`cmp latest.json public-latest.json`,
	}
	previous := -1
	for _, item := range requiredInOrder {
		position := strings.Index(workflow, item)
		if position < 0 {
			t.Fatalf("mirror high-assurance invariant missing: %s", item)
		}
		if position <= previous {
			t.Fatalf("mirror high-assurance publication order changed at: %s", item)
		}
		previous = position
	}
	stableStart := strings.Index(workflow, `- name: Confirm GitHub Latest before stable update`)
	stableEnd := strings.Index(workflow[stableStart:], `- name: Remove SSH identity`)
	stableStep := workflow[stableStart : stableStart+stableEnd]
	for _, item := range []string{
		`[[ "$BOOTSTRAP_PRESENT" == "1" ]]`,
		`[[ -z "$BOOTSTRAP_SIGNATURE_ASSET" || "$HIGH_ASSURANCE_BOOTSTRAP" == "1" ]]`,
		`"deploy/$TAG/sun.sh" "$MIRROR_USER@$MIRROR_HOST:sun.sh"`,
		`latest.json "$MIRROR_USER@$MIRROR_HOST:latest.json"`,
	} {
		if !strings.Contains(stableStep, item) {
			t.Fatalf("stable publication legacy-bootstrap guard missing: %s", item)
		}
	}
	if strings.Contains(stableStep, `release-signing.pub.asc`) {
		t.Fatal("stable publication must not pretend to atomically publish the versioned trust set")
	}
	for _, item := range []string{`mirror-lock.sh`, `REMOTE_SCRIPT`, `coproc `, `flock `} {
		if strings.Contains(stableStep, item) {
			t.Fatalf("forced-command rrsync publication must not execute remote code: %s", item)
		}
	}
}

func TestReleaseCIRequiresBootstrapVersionBinding(t *testing.T) {
	root := repositoryRoot(t)
	b, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(b)
	for _, item := range []string{
		`ref: ${{ github.workflow_sha }}`,
		`path: released-source`,
		assets.ReleaseSigningFingerprint,
		`pin="$expected_pin"`,
		`"rel/$archive" "$version" "$epoch" released-source`,
		`BOOTSTRAP_VERSION_NOTATION`,
		`--known-notation`,
		`NOTATION_NAME`,
		`NOTATION_FLAGS`,
		`NOTATION_DATA`,
		`--show-notation`,
		`expected_assets+=("$bootstrap_signature_asset")`,
		`--verify "rel/$BOOTSTRAP_SIGNATURE_ASSET" "$package_dir/sun.sh"`,
	} {
		if !strings.Contains(workflow, item) {
			t.Fatalf("release CI bootstrap-version invariant missing: %s", item)
		}
	}
}

func TestLiveCanaryIsolatesRunnerHealthAndSkipsFakeNotificationCredentialProbe(t *testing.T) {
	root := repositoryRoot(t)
	script, err := os.ReadFile(filepath.Join(root, "build", "live-canary.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []string{
		`install -m 0600 /dev/null "$canary_env"`,
		`install -m 0600 /dev/null "$telegram_token_file"`,
		`--env-file "$canary_env"`,
		`--telegram-token-file "$telegram_token_file"`,
		`CHECK_UPDATE_HEALTH=0`,
		`STALE_UPDATE_DAYS=0`,
		`PENDING_ALERT_DAYS=0`,
		`RESTART_ALERT_DAYS=0`,
		`CHECK_EOL=0`,
		`CHECK_SELF_UPDATE=0`,
		`matches="$(grep -c "^${key}=" /etc/security-update-notify/telegram.env || :)"`,
		`grep -qxF "$expected" /etc/security-update-notify/telegram.env`,
		`apt_check=(apt-get -o DPkg::Lock::Timeout=300 check -qq)`,
		`apt_check_before_rc="$(capture_bounded_rc "$work/apt-check.before" 330s "${apt_check[@]}")"`,
		`dpkg_audit_before_rc="$(capture_bounded_rc "$work/dpkg-audit.before" 60s dpkg --audit)"`,
		`apt_rc="$(capture_bounded_rc "$apt_output" 330s "${apt_check[@]}")"`,
		`dpkg_rc="$(capture_bounded_rc "$dpkg_output" 60s dpkg --audit)"`,
		`apt_policy_backup="${apt_policy}.security-update-notify.bak"`,
		`apt_policy_absent_marker="${apt_policy}.security-update-notify.absent.bak"`,
		`apt_policy_legacy_absent_marker="${apt_policy}.security-update-notify.absent"`,
		`apt_policy_dependency_proof="${apt_policy}.security-update-notify.dependency-default.bak"`,
		`assert_restored_apt_policy()`,
		`die "runner is not clean: SUN APT policy metadata already exists"`,
		`die "installed SUN APT baseline state is ambiguous"`,
		`die "SUN APT policy metadata remained after purge"`,
	} {
		if !bytes.Contains(script, []byte(item)) {
			t.Fatalf("live canary runner-isolation invariant missing: %s", item)
		}
	}
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "live-canary.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(workflow, []byte("  workflow_call:\n")) || bytes.Contains(workflow, []byte("  workflow_run:\n")) ||
		!bytes.Contains(workflow, []byte("- name: Require preinstalled GitHub CLI\n")) ||
		bytes.Contains(workflow, []byte("apt-get install -y gh")) {
		t.Fatal("live canary must be invoked as a dependency of a completed mirror job")
	}
	requiredInOrder := []string{
		`apt_check_before_rc="$(capture_bounded_rc "$work/apt-check.before" 330s "${apt_check[@]}")"`,
		`/bin/bash -p "$work/stable-sun.sh"`,
		`grep -qxF "$expected" /etc/security-update-notify/telegram.env ||`,
		`systemctl is-enabled --quiet security-update-notify.timer || die`,
		`systemctl is-active --quiet security-update-notify.timer || die`,
		"systemd-analyze verify \\\n  /etc/systemd/system/security-update-notify.service \\\n  /etc/systemd/system/security-update-notify.timer\n/usr/local/sbin/security-update-notify doctor --skip-notify --lang en\n",
		`assert_package_state_not_regressed after-install`,
		`case "$apt_policy_was_present:$apt_policy_backup_exists:$apt_policy_absent_marker_exists:$apt_policy_legacy_absent_marker_exists:$apt_policy_dependency_proof_exists" in`,
		`apt_policy_purge_expectation=original`,
		`apt_policy_purge_expectation=dependency-default`,
		`apt_policy_purge_expectation=absent`,
		`dry_run_output="$(/usr/local/sbin/security-update-notify run`,
		`grep -q $'^HASH\t' <<<"$dry_run_output" || die`,
		"/usr/local/sbin/security-update-notify uninstall --purge-config --lang en\n[[ ! -e /usr/local/sbin/security-update-notify ]] || die",
		`[[ ! -e /etc/security-update-notify ]] || die`,
		`[[ ! -e /var/lib/security-update-notify ]] || die`,
		`[[ ! -e /etc/systemd/system/security-update-notify.service ]] || die`,
		`[[ ! -e /etc/systemd/system/security-update-notify.timer ]] || die`,
		`assert_package_state_not_regressed after-purge`,
		`case "$apt_policy_purge_expectation" in`,
		`assert_restored_apt_policy "$work/apt-policy.before" "original APT policy"`,
		`assert_restored_apt_policy "$work/apt-policy.dependency-default" "retained dependency APT policy"`,
		`die "originally absent APT policy was not removed"`,
		`die "SUN APT policy metadata remained after purge"`,
	}
	previous := -1
	for _, item := range requiredInOrder {
		start := previous + 1
		relative := bytes.Index(script[start:], []byte(item))
		if relative < 0 {
			t.Fatalf("live canary hard lifecycle invariant missing: %s", item)
		}
		previous = start + relative
	}
}

func TestWorkflowImmutableReleaseChecksUseContentsReadAPI(t *testing.T) {
	root := repositoryRoot(t)
	for _, name := range []string{
		".github/workflows/ci.yml",
		".github/workflows/mirror-release.yml",
		"build/live-canary.sh",
	} {
		t.Run(name, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(content, []byte(`/immutable-releases`)) {
				t.Fatal("workflow must not call the administration-only immutable-releases endpoint")
			}
			if !bytes.Contains(content, []byte(`.immutable`)) {
				t.Fatal("workflow must require the current release immutable state")
			}
		})
	}
}

func TestBootstrapRuntimeVersionProbeIsBounded(t *testing.T) {
	root := repositoryRoot(t)
	script, err := os.ReadFile(filepath.Join(root, "sun.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte(`REQUIRED_COMMANDS=(curl tar sha256sum mktemp python3 env uname timeout wc)`),
		[]byte(`timeout --signal=TERM --kill-after=5s "$duration"`),
		[]byte(`capture_limited 4096 "$runtime_version_file" 15s "$GO_RUNTIME" --version`),
		[]byte(`command output exceeds size limit`),
	} {
		if !bytes.Contains(script, required) {
			t.Fatalf("bootstrap runtime-probe boundary missing %q", required)
		}
	}
	if bytes.Contains(script, []byte(`runtime_version="$($GO_RUNTIME --version`)) {
		t.Fatal("bootstrap runtime probe reverted to unbounded command substitution")
	}
}

func TestDocumentedHighAssuranceBlocksAreShellSyntaxValid(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	root := repositoryRoot(t)
	for _, name := range []string{"docs/installation.md", "docs/installation.en.md"} {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			block, ok := highAssuranceCommandBlock(b)
			if !ok {
				t.Fatal("high-assurance command block not found")
			}
			for _, required := range [][]byte{
				[]byte(`SUN_VERSION='X.Y.Z'`),
				[]byte(`PATH=/usr/sbin:/usr/bin:/sbin:/bin`),
				[]byte(assets.ReleaseSigningFingerprint),
				[]byte(`release-version@xxv.cc`),
				[]byte(`--known-notation`),
				[]byte(`--show-notation`),
				[]byte(`NOTATION_NAME`),
				[]byte(`NOTATION_FLAGS`),
				[]byte(`NOTATION_DATA`),
				[]byte(`part="${output}.part"`),
				[]byte(`remaining + 1`),
				[]byte(`open(path, "xb")`),
				[]byte(`rm -f -- "$part"`),
				[]byte(`mv -f -- "$part" "$output"`),
				[]byte(`--max-time 180`),
				[]byte(`--verify "$SUN_WORK/sun.sh.asc" "$SUN_WORK/sun.sh"`),
				[]byte(`/bin/bash -p "$SUN_WORK/sun.sh"`),
				[]byte(`--version "$SUN_VERSION" --base-url "$SUN_BASE"`),
			} {
				if !bytes.Contains(block, required) {
					t.Fatalf("documented trust-boundary command missing %q", required)
				}
			}
			cmd := exec.Command("bash", "-n")
			cmd.Stdin = bytes.NewReader(block)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("bash -n: %v: %s", err, output)
			}
		})
	}
}

func TestDocumentedHighAssuranceBlocksExecuteOnlyAfterRealGPGVerification(t *testing.T) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	signerHome := filepath.Join(t.TempDir(), "gnupg")
	if err := os.Mkdir(signerHome, 0o700); err != nil {
		t.Fatal(err)
	}
	goodFingerprint := generateBootstrapTestKey(t, ctx, gpg, signerHome, "SUN documented install <documented@example.invalid>")
	wrongFingerprint := generateBootstrapTestKey(t, ctx, gpg, signerHome, "SUN wrong install <wrong@example.invalid>")
	publicKey, err := runGPGOutput(ctx, gpg, signerHome, "--armor", "--export", "--", goodFingerprint)
	if err != nil {
		t.Fatalf("export bootstrap test key: %v", err)
	}
	fakeBin := writeBootstrapFakeCurl(t)
	root := repositoryRoot(t)
	version, err := ReadVersion(root)
	if err != nil {
		t.Fatal(err)
	}
	blocks := make(map[string][]byte, 2)
	for _, name := range []string{"docs/installation.md", "docs/installation.en.md"} {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		block, ok := highAssuranceCommandBlock(b)
		if !ok {
			t.Fatalf("high-assurance command block not found in %s", name)
		}
		blocks[name] = block
	}

	goodAssets := writeBootstrapTestAssets(t, ctx, gpg, signerHome, publicKey, goodFingerprint, []string{version}, false)
	for name, block := range blocks {
		t.Run(name+"/valid", func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "executed")
			output, err := runDocumentedHighAssuranceBlock(block, version, goodFingerprint, goodAssets, fakeBin, marker)
			if err != nil {
				t.Fatalf("verified documented install failed: %v: %s", err, output)
			}
			if got, err := os.ReadFile(marker); err != nil || string(got) != version+"\n" {
				t.Fatalf("verified bootstrap execution marker=(%q,%v)", got, err)
			}
		})
	}
	for name, block := range blocks {
		t.Run(name+"/oversized-chunked-download", func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "must-not-execute")
			output, err := runDocumentedHighAssuranceBlock(
				block, version, goodFingerprint, goodAssets, fakeBin, marker,
				"SUN_TEST_OVERSIZED_ASSET=sun.sh",
			)
			if err == nil {
				t.Fatalf("oversized bootstrap download was accepted: %s", output)
			}
			if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
				t.Fatalf("oversized bootstrap executed before download validation failed: %v", statErr)
			}
		})
	}

	wrongVersion := "0.0.0"
	if version == wrongVersion {
		wrongVersion = "0.0.1"
	}
	negative := []struct {
		name           string
		signer         string
		notationValues []string
		tamper         bool
	}{
		{name: "wrong-version", signer: goodFingerprint, notationValues: []string{wrongVersion}},
		{name: "missing-notation", signer: goodFingerprint},
		{name: "duplicate-notation", signer: goodFingerprint, notationValues: []string{version, version}},
		{name: "wrong-key", signer: wrongFingerprint, notationValues: []string{version}},
		{name: "tampered-script", signer: goodFingerprint, notationValues: []string{version}, tamper: true},
	}
	for _, tc := range negative {
		t.Run(tc.name, func(t *testing.T) {
			assetsDir := writeBootstrapTestAssets(
				t, ctx, gpg, signerHome, publicKey, tc.signer, tc.notationValues, tc.tamper,
			)
			for name, block := range blocks {
				t.Run(name, func(t *testing.T) {
					marker := filepath.Join(t.TempDir(), "must-not-execute")
					output, err := runDocumentedHighAssuranceBlock(
						block, version, goodFingerprint, assetsDir, fakeBin, marker,
					)
					if err == nil {
						t.Fatalf("invalid bootstrap trust set was accepted: %s", output)
					}
					if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
						t.Fatalf("bootstrap executed before verification failed: %v", statErr)
					}
				})
			}
		})
	}
}

func generateBootstrapTestKey(t *testing.T, ctx context.Context, gpg, home, identity string) string {
	t.Helper()
	if err := runGPG(ctx, gpg, home,
		"--pinentry-mode", "loopback", "--passphrase", "",
		"--quick-generate-key", identity, "ed25519", "sign", "0",
	); err != nil {
		t.Fatalf("generate bootstrap test key: %v", err)
	}
	fingerprint, err := secretKeyFingerprint(ctx, gpg, home, identity)
	if err != nil {
		t.Fatalf("read bootstrap test fingerprint: %v", err)
	}
	return fingerprint
}

func writeBootstrapTestAssets(
	t *testing.T,
	ctx context.Context,
	gpg, signerHome string,
	publicKey []byte,
	signer string,
	notationValues []string,
	tamper bool,
) string {
	t.Helper()
	dir := t.TempDir()
	script := []byte("#!/usr/bin/env bash\nset -euo pipefail\n" +
		"[[ \"$#\" -eq 4 && \"$1\" == --version && \"$2\" == \"$SUN_EXPECTED_VERSION\" " +
		"&& \"$3\" == --base-url ]]\n" +
		"printf '%s\\n' \"$2\" > \"$SUN_EXEC_MARKER\"\n")
	scriptPath := filepath.Join(dir, "sun.sh")
	if err := os.WriteFile(scriptPath, script, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "release-signing.pub.asc"), publicKey, 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"--yes", "--armor", "--detach-sign", "--local-user", signer}
	for _, value := range notationValues {
		args = append(args, "--sig-notation", "!"+bootstrapVersionNotation+"="+value)
	}
	args = append(args, "-o", filepath.Join(dir, bootstrapSignatureName), "--", scriptPath)
	if err := runGPG(ctx, gpg, signerHome, args...); err != nil {
		t.Fatalf("sign documented bootstrap fixture: %v", err)
	}
	if tamper {
		tampered := bytes.Replace(script, []byte("$SUN_EXPECTED_VERSION"), []byte("tampered"), 1)
		if err := os.WriteFile(scriptPath, tampered, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func writeBootstrapFakeCurl(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/usr/bin/env bash
set -euo pipefail
output=''
url=''
while (($#)); do
  case "$1" in
    --output)
      output="${2:?missing curl output path}"
      shift 2
      ;;
    *)
      url="$1"
      shift
      ;;
  esac
done
[[ -n "$url" ]]
asset="${url##*/}"
if [[ "${SUN_TEST_OVERSIZED_ASSET:-}" == "$asset" ]]; then
  python3 -c 'import sys; sys.stdout.buffer.write(b"x" * 1048577)'
elif [[ -n "$output" ]]; then
  cp -- "$SUN_TEST_ASSET_DIR/$asset" "$output"
else
  cat -- "$SUN_TEST_ASSET_DIR/$asset"
fi
`
	if err := os.WriteFile(filepath.Join(dir, "curl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runDocumentedHighAssuranceBlock(
	block []byte, version, fingerprint, assetsDir, fakeBin, marker string, extraEnv ...string,
) ([]byte, error) {
	script := strings.Replace(string(block), "sudo /bin/bash -p <<'SUN_ROOT'", "/bin/bash -p <<'SUN_ROOT'", 1)
	script = strings.Replace(script, "SUN_VERSION='X.Y.Z'", "SUN_VERSION='"+version+"'", 1)
	script = strings.Replace(script, assets.ReleaseSigningFingerprint, fingerprint, 1)
	// The published block deliberately fixes a privileged PATH. Only the test
	// copy prepends the fixture directory so its fake curl can supply local
	// signed assets without weakening the documented command.
	script = strings.Replace(script,
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"PATH="+fakeBin+":/usr/sbin:/usr/bin:/sbin:/bin",
		1,
	)
	cmd := exec.Command("bash")
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(os.Environ(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"SUN_TEST_ASSET_DIR="+assetsDir,
		"SUN_EXEC_MARKER="+marker,
		"SUN_EXPECTED_VERSION="+version,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	return cmd.CombinedOutput()
}

func highAssuranceCommandBlock(readme []byte) ([]byte, bool) {
	startMarker := []byte("sudo /bin/bash -p <<'SUN_ROOT'\n")
	start := bytes.Index(readme, startMarker)
	if start < 0 {
		return nil, false
	}
	endMarker := []byte("\nSUN_ROOT\n")
	relativeEnd := bytes.Index(readme[start:], endMarker)
	if relativeEnd < 0 {
		return nil, false
	}
	end := start + relativeEnd + len(endMarker)
	return append([]byte(nil), readme[start:end]...), true
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
}
