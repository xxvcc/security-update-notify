// Package dedup 复刻告警去重：alert_hash 是对 11 个稳定字段做 sha256（每个字段后跟一个 '\n'，
// 末尾也有 '\n'），ShouldSend 实现 once/daily/interval 抑制，Store 以“临时文件 + 原子重命名”落盘状态
// （hash 先于时间戳，崩溃只会更倾向发送，绝不静默抑制真实告警）。这是全 Go 端口 make-or-break 的核心：
// 任一字段的一字节漂移都会让每台已装机器在升级后重复告警一次。
//
// Package dedup reproduces alert deduplication: alert_hash is sha256 over 11 stable fields (each followed
// by '\n', with a trailing '\n' after the last), ShouldSend implements once/daily/interval suppression,
// and Store persists state via temp-file + atomic rename (hash before timestamp, so a crash only biases
// toward sending). Make-or-break: a one-byte drift in any field re-alerts every installed host once.
package dedup

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Fields 是进入 alert_hash 的 11 个字段（顺序固定，与运行时 printf 一致）。
type Fields struct {
	Host             string
	Backend          string
	NotifyLang       string
	RebootRequired   bool
	RebootPkgs       string
	RestartAttention bool
	RestartSignal    string
	HealthAttention  bool
	HealthSig        string
	EolAttention     bool
	EolSig           string
}

func b01(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// Hash 计算 alert_hash：按固定顺序把 11 个字段各追加一个 '\n'（含末尾 '\n'）后 sha256，取小写十六进制。
// 等价于 Bash 的 `printf '%s\n%s\n...(11)' ... | sha256sum | awk '{print $1}'`。
func Hash(f Fields) string {
	var b strings.Builder
	for _, s := range []string{
		f.Host, f.Backend, f.NotifyLang,
		b01(f.RebootRequired), f.RebootPkgs, b01(f.RestartAttention), f.RestartSignal,
		b01(f.HealthAttention), f.HealthSig, b01(f.EolAttention), f.EolSig,
	} {
		b.WriteString(s)
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// ShouldSend 复刻发送决策：--no-dedupe 或 hash 变化 → 发送；否则按模式抑制。
//   - once（旧名 always）：同一 hash 只发一次（状态变化前不再发）；
//   - daily：同一 hash 每个本地日历日最多一次；
//   - interval（及未知模式的兜底）：同一 hash 每 intervalDays 天一次。
//
// intervalDays 无效（<1）时按 3 处理，模式为空时按 daily（由调用方规范化）。
func ShouldSend(noDedupe bool, curHash, lastHash string, lastSent, now int64, mode string, intervalDays int) bool {
	if noDedupe || curHash != lastHash {
		return true
	}
	switch mode {
	case "once", "always":
		return false
	case "daily":
		return localDay(lastSent) != localDay(now)
	default: // interval 及未知模式兜底
		if intervalDays < 1 {
			intervalDays = 3
		}
		if now-lastSent < int64(intervalDays)*86400 {
			return false
		}
		return true
	}
}

func localDay(epoch int64) string {
	return time.Unix(epoch, 0).Format("2006-01-02")
}

// Store 管理去重状态文件（hash 与发送时间戳）。
type Store struct {
	Dir      string
	HashFile string
	TimeFile string
}

// NewStore 按运行时的路径约定构造：<dir>/last-alert.sha256 与 <dir>/last-alert.sent_at。
func NewStore(dir string) *Store {
	return &Store{
		Dir:      dir,
		HashFile: filepath.Join(dir, "last-alert.sha256"),
		TimeFile: filepath.Join(dir, "last-alert.sent_at"),
	}
}

// ReadLast 读回上次 hash 与发送时间戳；缺失或非法时分别返回 ""、0。回读会裁掉所有尾部换行
// （Bash 用 `cat` 捕获，若不裁，Go 会误判为不同 hash 而每次重发）。
func (s *Store) ReadLast() (hash string, sentAt int64) {
	if b, err := os.ReadFile(s.HashFile); err == nil {
		hash = strings.TrimRight(string(b), "\n")
	}
	if b, err := os.ReadFile(s.TimeFile); err == nil {
		if n, err := strconv.ParseInt(strings.TrimRight(string(b), "\n"), 10, 64); err == nil {
			sentAt = n
		}
	}
	return hash, sentAt
}

// Write 原子写状态：临时文件 + rename，hash 先于时间戳落盘；任一步失败回退到显式 0600 直写，保持
// 与运行时一致的健壮性（崩溃/磁盘满不留下被截断的状态文件）。
func (s *Store) Write(hash string, now int64) error {
	if err := s.atomic(s.HashFile, hash+"\n"); err == nil {
		if err := s.atomic(s.TimeFile, strconv.FormatInt(now, 10)+"\n"); err == nil {
			return nil
		}
	}
	// 回退：显式 0600 直写。
	if err := os.WriteFile(s.HashFile, []byte(hash+"\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(s.TimeFile, []byte(strconv.FormatInt(now, 10)+"\n"), 0o600)
}

func (s *Store) atomic(dest, content string) error {
	tmp, err := os.CreateTemp(s.Dir, ".state.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
