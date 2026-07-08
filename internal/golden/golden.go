// Package golden 提供由“真·Bash 运行时”捕获的黄金向量（known-answer vectors）：给定受控场景，
// files/security-update-notify 实际写入 STATE_FILE 的去重 alert_hash，以及归一化后的 Telegram 正文。
// 这是全 Go 端口 make-or-break 的 oracle——Phase 1 的 internal/dedup 与 internal/notify 必须逐字节复刻。
// 向量由 build/golden/capture.sh 生成；不要手改 testdata/scenarios.json。
//
// Package golden provides known-answer vectors captured from the REAL Bash runtime: for a controlled
// scenario, the dedup alert_hash that files/security-update-notify actually writes to STATE_FILE, plus the
// normalized Telegram body. This is the make-or-break oracle for the full Go port — Phase 1's
// internal/dedup and internal/notify must reproduce both byte-for-byte. Regenerate via
// build/golden/capture.sh; do not hand-edit testdata/scenarios.json.
package golden

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed testdata/scenarios.json
var rawVectors []byte

// Vector 是单个受控场景的期望结果。Hash 是 64 位小写十六进制的 alert_hash；Message 是归一化后的
// 正文（易变行 系统/OS、当前内核/kernel、时间/Time 已替换为占位符 <OS>/<KERNEL>/<NOW>），OK 路径下
// 未发送则 Message 为空。
//
// Vector is the expected result for one controlled scenario. Hash is the 64-lowercase-hex alert_hash;
// Message is the normalized body (volatile OS/kernel/time lines replaced with <OS>/<KERNEL>/<NOW>
// placeholders), empty when the OK path did not send.
type Vector struct {
	Name    string `json:"name"`
	Hash    string `json:"hash"`
	Message string `json:"message"`
}

// Vectors 解析并返回内嵌的黄金向量集合。
func Vectors() ([]Vector, error) {
	var v []Vector
	if err := json.Unmarshal(rawVectors, &v); err != nil {
		return nil, fmt.Errorf("parse golden vectors: %w", err)
	}
	return v, nil
}

// ByName 返回以场景名为键的向量表，便于按名断言。
func ByName() (map[string]Vector, error) {
	vs, err := Vectors()
	if err != nil {
		return nil, err
	}
	m := make(map[string]Vector, len(vs))
	for _, v := range vs {
		m[v.Name] = v
	}
	return m, nil
}
