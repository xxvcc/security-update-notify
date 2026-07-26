// Package golden 提供迁移期间从 2.x Bash 运行时捕获并冻结的黄金向量（known-answer vectors）：
// 给定受控场景，记录其 STATE_FILE 去重 alert_hash 与归一化后的 Telegram 正文。这些向量用于阻止
// 全 Go 实现意外改变兼容输出；原捕获器和 Bash 运行时已在 3.0.0 中删除。
//
// Package golden provides frozen known-answer vectors captured from the 2.x Bash runtime during the
// migration. They record the dedup alert_hash and normalized Telegram body for controlled scenarios and
// prevent the all-Go implementation from accidentally changing compatible output. The capture tool and
// Bash runtime were removed in 3.0.0.
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
