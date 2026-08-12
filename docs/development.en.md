# Development and local validation

[中文](development.md) | [Back to README](../README.en.md)

This guide is only for contributors and maintainers. Normal installation and operations do not require these commands. Run the gates below from a complete Git source checkout; signed release archives intentionally omit the `cmd/`, `internal/`, `build/`, and workflow sources.

## Validate source changes

The following gates can run while the source checkout still has uncommitted changes:

```bash
set -euo pipefail
bash -n sun.sh build/*.sh
shellcheck -s bash -S info sun.sh build/*.sh
unformatted="$(find cmd internal -type f -name '*.go' -print0 | sort -z | xargs -0 gofmt -l)"
test -z "$unformatted"
git diff --check
git diff --check "$(git hash-object -t tree /dev/null)" HEAD --
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
coverage_file="$(mktemp /tmp/security-update-notify-coverage.XXXXXX)"
trap 'rm -f -- "$coverage_file"' EXIT
go test -race -covermode=atomic -coverprofile="$coverage_file" ./...
total="$(go tool cover -func="$coverage_file" | awk '/^total:/ {sub(/%$/, "", $3); print $3}')"
awk -v total="$total" 'BEGIN { exit !(total + 0 >= 75.0) }'
build/archive-safety-test.sh
build/reproducibility-check.sh linux amd64
docker run --rm -e SUN_CONTAINER_TEST=1 -v "$PWD:/src:ro" debian:12 bash /src/build/compat-test.sh
docker run --rm -e SUN_CONTAINER_TEST=1 -v "$PWD:/src:ro" debian:12 bash /src/build/rollback-test.sh
docker run --rm -e SUN_CONTAINER_TEST=1 -v "$PWD:/src:ro" debian:12 bash /src/build/interactive-test.sh
rm -f -- "$coverage_file"
trap - EXIT
```

`build/runtime-lock-test.sh` must run as a non-root user. An unprivileged maintainer can invoke it directly.
When the maintenance shell is root, copy the current worktree to an isolated directory under `/tmp` and run it
as unprivileged UID/GID 65534; never recursively change ownership of the original worktree:

```bash
set -euo pipefail
if (( EUID == 0 )); then
  runtime_gate="$(mktemp -d /tmp/security-update-notify-runtime-gate.XXXXXX)"
  chmod 0700 "$runtime_gate"
  trap 'rm -rf -- "$runtime_gate"' EXIT
  source_root="$(pwd -P)"
  source_candidates="$runtime_gate/source-candidates"
  source_list="$runtime_gate/source-files"
  git ls-files --cached --others --exclude-standard -z >"$source_candidates"
  : >"$source_list"
  while IFS= read -r -d '' source; do
    [[ "$source" != /* && "$source" != .. && "$source" != ../* ]]
    if [[ ! -e "$source" && ! -L "$source" ]]; then
      continue
    fi
    [[ -f "$source" && ! -L "$source" ]]
    resolved_source="$(realpath -e -- "$source")"
    [[ "$resolved_source" == "$source_root/$source" ]]
    printf '%s\0' "$source" >>"$source_list"
  done <"$source_candidates"
  install -d "$runtime_gate/src"
  rsync -a --from0 --files-from="$source_list" --relative \
    ./ "$runtime_gate/src/"
  install -d "$runtime_gate/home" "$runtime_gate/cache" \
    "$runtime_gate/gomod" "$runtime_gate/tmp"
  chown -R 65534:65534 "$runtime_gate"
  setpriv --reuid=65534 --regid=65534 --clear-groups \
    env HOME="$runtime_gate/home" GOCACHE="$runtime_gate/cache" \
      GOMODCACHE="$runtime_gate/gomod" TMPDIR="$runtime_gate/tmp" \
      "$runtime_gate/src/build/runtime-lock-test.sh"
  rm -rf -- "$runtime_gate"
  trap - EXIT
else
  build/runtime-lock-test.sh
fi
```

## Validate the clean release commit

The release packager rejects uncommitted release sources. After committing, run the unsigned packaging gate
separately on the exact clean release commit. Do not reuse the repository's `dist/`, which may contain stale files:

```bash
set -euo pipefail
[[ -z "$(git status --porcelain=v1)" ]]
package_epoch="$(git show -s --format=%ct HEAD)"
package_dist="$(mktemp -d /tmp/security-update-notify-package.XXXXXX)"
go run ./cmd/sun-release package --sign off \
  --source-date-epoch "$package_epoch" --dist "$package_dist"
(cd "$package_dist" && sha256sum -c security-update-notify-*.tar.gz.sha256)
[[ "$(find "$package_dist" -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 2 ]]
```

`build/compat-test.sh`, `build/rollback-test.sh`, `build/interactive-test.sh`, `build/rocky-bootstrap-test.sh`, `build/rpm-best-effort-test.sh`, and `build/dnf5-versionlock-test.sh` modify system paths and must only run in disposable Docker containers, never directly on the host. An official release must also pass CI's five-architecture execution, hostile-archive, signature, and public-asset verification gates.

CI uses a documentation/version-binding fast path for documentation-only changes. Source, build-script, workflow, and release-input changes retain the complete quality, distribution-lifecycle, and five-architecture gates. See [3.x Go architecture](go-port.md) for the architecture and gate invariants.

## Related documentation

- [Maintainer release process](releasing.en.md)
- [3.x Go architecture](go-port.md)
