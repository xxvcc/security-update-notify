module github.com/xxvcc/security-update-notify

// go 声明语言下限；toolchain 固定实际构建工具链版本，配合 CI 的 GOTOOLCHAIN=local
// 保证可复现构建（否则 Go 静默升级工具链会改变每个产物的 sha256）。
// The go directive is the language floor; toolchain pins the actual build toolchain so that,
// with GOTOOLCHAIN=local in CI, builds are reproducible (a silent Go toolchain bump would
// otherwise change every artifact's sha256).
go 1.23

toolchain go1.26.4
