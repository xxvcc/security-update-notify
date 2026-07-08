// Command security-update-notify 是 SUN 的 Go 二进制入口。分发逻辑在 internal/cli；裸调用即运行检查，
// 保留 --test-ok/--test-reboot/--no-dedupe/--lang/--version 与信任 helper 子命令（version-newer/verify/
// check-archive）。--doctor/--check-upgrade/--upgrade 正在移植（见 docs/go-port.md）。
//
// Command security-update-notify is SUN's Go binary entrypoint. Dispatch lives in internal/cli; a bare
// invocation runs the check, keeping --test-ok/--test-reboot/--no-dedupe/--lang/--version and the trust
// helper subcommands. --doctor/--check-upgrade/--upgrade are being ported (see docs/go-port.md).
package main

import (
	"os"

	"github.com/xxvcc/security-update-notify/internal/cli"
)

// Version 由 -ldflags "-X main.Version=X.Y.Z" 在编译期注入；刻意不可被环境变量覆盖。
// Version is injected at build time via -ldflags "-X main.Version=X.Y.Z"; deliberately not env-overridable.
var Version = "dev"

func main() {
	os.Exit(cli.Main(Version, os.Args[1:]))
}
