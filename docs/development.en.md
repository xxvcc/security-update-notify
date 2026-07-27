# Development and local validation

[中文](development.md) | [Back to README](../README.en.md)

This guide is only for contributors and maintainers. Normal installation and operations do not require these commands. Run the gates below from a complete Git source checkout; signed release archives intentionally omit the `cmd/`, `internal/`, `build/`, and workflow sources.

## Build a release package

From the source checkout:

```bash
bash -n sun.sh build/*.sh
shellcheck -s bash -S info sun.sh build/*.sh
unformatted="$(find cmd internal -type f -name '*.go' -print0 | sort -z | xargs -0 gofmt -l)"
test -z "$unformatted"
git diff --check
git diff --check "$(git hash-object -t tree /dev/null)" HEAD --
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go test -race -covermode=atomic -coverprofile=coverage.out ./...
total="$(go tool cover -func=coverage.out | awk '/^total:/ {sub(/%$/, "", $3); print $3}')"
awk -v total="$total" 'BEGIN { exit !(total + 0 >= 75.0) }'
build/archive-safety-test.sh
build/runtime-lock-test.sh
build/reproducibility-check.sh linux amd64
docker run --rm -e SUN_CONTAINER_TEST=1 -v "$PWD:/src:ro" debian:12 bash /src/build/compat-test.sh
docker run --rm -e SUN_CONTAINER_TEST=1 -v "$PWD:/src:ro" debian:12 bash /src/build/rollback-test.sh
go run ./cmd/sun-release package
cd dist && sha256sum -c security-update-notify-*.tar.gz.sha256
```

`build/compat-test.sh`, `build/rollback-test.sh`, `build/interactive-test.sh`, `build/rocky-bootstrap-test.sh`, and `build/rpm-best-effort-test.sh` modify system paths and must only run in disposable Docker containers, never directly on the host. An official release must also pass CI's five-architecture execution, hostile-archive, signature, and public-asset verification gates.

CI uses a documentation/version-binding fast path for documentation-only changes. Source, build-script, workflow, and release-input changes retain the complete quality, distribution-lifecycle, and five-architecture gates. See [3.x Go architecture](go-port.md) for the architecture and gate invariants.

## Related documentation

- [Maintainer release process](releasing.en.md)
- [3.x Go architecture](go-port.md)
