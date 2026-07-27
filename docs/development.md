# 开发与本地验证

[English](development.en.md) | [返回 README](../README.md)

本页只面向贡献者和维护者。普通安装和日常运维不需要执行这些命令。以下门禁必须在完整 Git 源码检出中运行；签名发行归档刻意不包含 `cmd/`、`internal/`、`build/` 或 workflow 源文件。

## 构建发布包

在源码目录运行：

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

`build/compat-test.sh`、`build/rollback-test.sh`、`build/interactive-test.sh`、`build/rocky-bootstrap-test.sh` 和 `build/rpm-best-effort-test.sh` 会修改系统路径，只能在一次性 Docker 容器中运行，禁止直接在宿主机执行。正式发布还必须完成 CI 的五架构实跑、恶意归档、签名和公开资产复验门禁。

CI 会对纯文档变更运行文档结构和版本绑定快速门禁；源码、构建脚本、workflow 或发布输入变化仍运行完整质量、发行版生命周期和五架构门禁。具体架构与门禁不变量见 [3.x Go 架构](go-port.md)。

## 相关文档

- [发布维护流程](releasing.md)
- [3.x Go 架构](go-port.md)
