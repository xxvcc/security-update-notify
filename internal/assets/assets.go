// Package assets 内置（go:embed）Go 运行时需要的静态资源：release 签名公钥（自升级验签用）、systemd
// 单元与 needrestart/logrotate 配置（未来 Go 安装器写盘用），并 pin release 签名指纹常量（刻意编译期
// 固定、不可被环境变量覆盖）。
//
// embed/ 下的文件是 files/ 与仓库根同名文件的受管副本；CI 的“Embedded assets drift guard”断言二者
// 逐字节一致，避免漂移（与 Bash 侧内联公钥有多份且 CI 守卫相等 是同一模式）。
//
// Package assets embeds the static resources the Go runtime needs (release signing public key for
// self-upgrade verification; systemd unit and needrestart/logrotate config for a future Go installer) and
// pins the release signing fingerprint constant (compile-time, not env-overridable). Files under embed/
// are managed copies of the originals under files/; a CI drift guard asserts they are byte-identical.
package assets

import _ "embed"

// ReleaseSigningFingerprint 是 release 签名公钥的 pin 指纹（40 位十六进制，大写）。刻意为常量。
const ReleaseSigningFingerprint = "C678256ACBFC6491BF5076655F3AE24999921FFC"

//go:embed embed/release-signing.pub.asc
var releaseSigningPubKey []byte

//go:embed embed/security-update-notify.service
var systemdService []byte

//go:embed embed/needrestart-report-only.conf
var needrestartConf []byte

//go:embed embed/security-update-notify.logrotate
var logrotateConf []byte

// ReleaseSigningPublicKey 返回内置的 ASCII-armored 签名公钥。
func ReleaseSigningPublicKey() []byte { return releaseSigningPubKey }

// SystemdServiceUnit 返回内置的 systemd service 单元内容。
func SystemdServiceUnit() []byte { return systemdService }

// NeedrestartConf 返回内置的 needrestart “仅报告” 配置。
func NeedrestartConf() []byte { return needrestartConf }

// LogrotateConf 返回内置的 logrotate 配置。
func LogrotateConf() []byte { return logrotateConf }
