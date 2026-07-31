// Package assets 内置（go:embed）Go 运行时与安装器需要的静态资源：release 签名公钥、systemd
// 单元与 needrestart/logrotate 配置，并 pin release 签名指纹常量（刻意编译期固定、不可被环境变量覆盖）。
//
// embed/ 下的文件是 files/ 与仓库根同名文件的受管副本；CI 的“Embedded assets drift guard”断言二者
// 逐字节一致，避免已签发布包与安装器写盘内容漂移。
//
// Package assets embeds the static resources the Go runtime needs (release signing public key for
// self-upgrade verification; systemd unit and needrestart/logrotate config for the Go installer) and
// pins the release signing fingerprint constant (compile-time, not env-overridable). Files under embed/
// are managed copies of the originals under files/; a CI drift guard asserts they are byte-identical.
package assets

import (
	"bytes"
	_ "embed"
)

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
func ReleaseSigningPublicKey() []byte { return bytes.Clone(releaseSigningPubKey) }

// SystemdServiceUnit 返回内置的 systemd service 单元内容。
func SystemdServiceUnit() []byte { return bytes.Clone(systemdService) }

// NeedrestartConf 返回内置的 needrestart “仅报告” 配置。
func NeedrestartConf() []byte { return bytes.Clone(needrestartConf) }

// LogrotateConf 返回内置的 logrotate 配置。
func LogrotateConf() []byte { return bytes.Clone(logrotateConf) }
