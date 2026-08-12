# 开发与本地验证

[English](development.en.md) | [返回 README](../README.md)

本页只面向贡献者和维护者。普通安装和日常运维不需要执行这些命令。以下门禁必须在完整 Git 源码检出中运行；签名发行归档刻意不包含 `cmd/`、`internal/`、`build/` 或 workflow 源文件。

## 验证源码变更

以下门禁可以在仍有未提交变更的源码目录运行：

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

`build/runtime-lock-test.sh` 必须以非 root 身份运行。普通用户可以直接执行它；维护 shell 为 root 时，先把当前
工作树复制到 `/tmp` 的隔离目录，再以无特权 UID/GID 65534 运行，不能对原工作树递归改所有者：

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

## 验证干净的发布提交

发布打包器会拒绝未提交的发布源。提交后在工作区干净的精确发布提交上单独运行 unsigned 打包门禁，不要复用
仓库内可能含有旧文件的 `dist/`：

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

`build/compat-test.sh`、`build/rollback-test.sh`、`build/interactive-test.sh`、`build/rocky-bootstrap-test.sh`、`build/rpm-best-effort-test.sh` 和 `build/dnf5-versionlock-test.sh` 会修改系统路径，只能在一次性 Docker 容器中运行，禁止直接在宿主机执行。正式发布还必须完成 CI 的五架构实跑、恶意归档、签名和公开资产复验门禁。

CI 会对纯文档变更运行文档结构和版本绑定快速门禁；源码、构建脚本、workflow 或发布输入变化仍运行完整质量、发行版生命周期和五架构门禁。具体架构与门禁不变量见 [3.x Go 架构](go-port.md)。

## 相关文档

- [发布维护流程](releasing.md)
- [3.x Go 架构](go-port.md)
