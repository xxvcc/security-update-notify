// Command security-update-notify 是 SUN 的 Go 二进制入口。分发逻辑在 internal/cli；裸调用即运行检查，
// install/configure/run/doctor/check-upgrade/upgrade/test/uninstall 与信任 helper 均由同一二进制提供。
//
// Command security-update-notify is SUN's Go binary entrypoint. Dispatch lives in internal/cli; a bare
// invocation runs the check, and the same binary provides install, configure, run, doctor, upgrade, test,
// uninstall, and the trust-helper subcommands.
package main

import (
	"os"

	"github.com/xxvcc/security-update-notify/internal/cli"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

// Version 由 -ldflags "-X main.Version=X.Y.Z" 在编译期注入；刻意不可被环境变量覆盖。
// Version is injected at build time via -ldflags "-X main.Version=X.Y.Z"; deliberately not env-overridable.
var Version = "dev"

func main() {
	sysexec.InstallSignalForwarding()
	os.Exit(cli.Main(Version, os.Args[1:]))
}
