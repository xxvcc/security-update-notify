// Package dedup 复刻告警去重：alert_hash 是对 11 个稳定字段做 sha256（每个字段后跟一个 '\n'，
// 末尾也有 '\n'），ShouldSend 实现 once/daily/interval 抑制，Store 以“临时文件 + 原子重命名”落盘状态
// （时间戳先于 hash，崩溃只会更倾向发送，绝不静默抑制真实告警）。这是全 Go 端口 make-or-break 的核心：
// 任一字段的一字节漂移都会让每台已装机器在升级后重复告警一次。
//
// Package dedup reproduces alert deduplication: alert_hash is sha256 over 11 stable fields (each followed
// by '\n', with a trailing '\n' after the last), ShouldSend implements once/daily/interval suppression,
// and Store persists state via temp-file + atomic rename (timestamp before hash, so a crash only biases
// toward sending). Make-or-break: a one-byte drift in any field re-alerts every installed host once.
package dedup

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/security-update-notify/internal/filetrust"
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
		if lastSent <= 0 || lastSent > now {
			return true
		}
		return localDay(lastSent) != localDay(now)
	default: // interval 及未知模式兜底
		if lastSent <= 0 || lastSent > now {
			return true
		}
		if intervalDays < 1 {
			intervalDays = 3
		}
		const secondsPerDay int64 = 86400
		const maxInt64 = int64(^uint64(0) >> 1)
		if int64(intervalDays) > maxInt64/secondsPerDay {
			return false
		}
		intervalSeconds := int64(intervalDays) * secondsPerDay
		if now < lastSent || uint64(now)-uint64(lastSent) < uint64(intervalSeconds) {
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
	Dir                string
	HashFile           string
	TimeFile           string
	TargetFile         string
	TargetPendingFile  string
	afterDirectoryOpen func()
	fileSync           func(*os.File) error
	directorySync      func(*os.File) error
}

// NewStore 按运行时的 Telegram 路径约定构造去重与目标状态。
func NewStore(dir string) *Store {
	return &Store{
		Dir:               dir,
		HashFile:          filepath.Join(dir, "last-alert.sha256"),
		TimeFile:          filepath.Join(dir, "last-alert.sent_at"),
		TargetFile:        filepath.Join(dir, "last-alert.telegram.target.sha256"),
		TargetPendingFile: filepath.Join(dir, "last-alert.telegram.target.pending"),
	}
}

// NewChannelStore constructs an independent store for a non-legacy channel. Telegram deliberately
// keeps using NewStore so an upgrade does not forget its existing delivery state and resend alerts.
func NewChannelStore(dir, channel string) *Store {
	return &Store{
		Dir:               dir,
		HashFile:          filepath.Join(dir, "last-alert."+channel+".sha256"),
		TimeFile:          filepath.Join(dir, "last-alert."+channel+".sent_at"),
		TargetFile:        filepath.Join(dir, "last-alert."+channel+".target.sha256"),
		TargetPendingFile: filepath.Join(dir, "last-alert."+channel+".target.pending"),
	}
}

// TargetFingerprint creates a domain-separated, unambiguous fingerprint for a
// channel's stable delivery identity. Callers must pass only stable identifiers
// (for example Telegram bot ID plus chat ID), never a bearer token or secret.
func TargetFingerprint(channel string, identities ...string) string {
	h := sha256.New()
	writePart := func(value string) {
		_, _ = io.WriteString(h, strconv.Itoa(len(value)))
		_, _ = io.WriteString(h, ":")
		_, _ = io.WriteString(h, value)
	}
	writePart("security-update-notify-target-v1")
	writePart(channel)
	for _, identity := range identities {
		writePart(identity)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TargetStatus describes how the current target relates to persisted delivery
// state. A missing fingerprint is Legacy so upgrading old state does not resend
// every unchanged alert. Pending and malformed state are Changed and therefore
// bias toward delivery.
type TargetStatus uint8

const (
	TargetLegacy TargetStatus = iota
	TargetCurrent
	TargetChanged
)

// ReadTargetStatus compares current with the last successfully delivered
// target. The pending marker is deliberately identity-free and forces another
// attempt after an installer change or interrupted state commit.
func (s *Store) ReadTargetStatus(current string) TargetStatus {
	if !validFingerprint(current) {
		return TargetChanged
	}
	targetName, err := s.entryName(s.TargetFile)
	if err != nil {
		return TargetChanged
	}
	pendingName, err := s.entryName(s.TargetPendingFile)
	if err != nil {
		return TargetChanged
	}
	directory, exists, err := s.openDirectory()
	if err != nil || !exists {
		return TargetChanged
	}
	defer directory.Close()
	if _, err := readStateFileAt(directory, pendingName, 64, os.Geteuid()); err == nil {
		return TargetChanged
	} else if !errors.Is(err, os.ErrNotExist) {
		return TargetChanged
	}
	b, err := readStateFileAt(directory, targetName, 256, os.Geteuid())
	if errors.Is(err, os.ErrNotExist) {
		return TargetLegacy
	}
	if err != nil {
		return TargetChanged
	}
	stored := strings.TrimRight(string(b), "\n")
	if !validFingerprint(stored) || stored != current {
		return TargetChanged
	}
	return TargetCurrent
}

// AdoptLegacyTarget binds target-less legacy state to the current stable
// identity without recording a delivery. Callers use this only after the
// existing hash/time policy has suppressed an alert, preserving upgrade
// compatibility while closing the migration window for later target changes.
func (s *Store) AdoptLegacyTarget(current string) error {
	if !validFingerprint(current) {
		return fmt.Errorf("invalid delivery target fingerprint")
	}
	targetName, err := s.entryName(s.TargetFile)
	if err != nil {
		return err
	}
	pendingName, err := s.entryName(s.TargetPendingFile)
	if err != nil {
		return err
	}
	directory, exists, err := s.openDirectory()
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("state directory does not exist: %s", s.Dir)
	}
	defer directory.Close()
	if _, err := readStateFileAt(directory, pendingName, 64, os.Geteuid()); err == nil {
		return fmt.Errorf("delivery target has a pending change")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read delivery target pending marker: %w", err)
	}
	stored, err := readStateFileAt(directory, targetName, 256, os.Geteuid())
	if err == nil {
		if strings.TrimRight(string(stored), "\n") == current {
			return nil
		}
		return fmt.Errorf("delivery target is no longer legacy")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read delivery target fingerprint: %w", err)
	}
	if err := s.atomicAt(directory, targetName, current+"\n"); err != nil {
		return fmt.Errorf("adopt legacy delivery target: %w", err)
	}
	return nil
}

func validFingerprint(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

// ReadLast 读回上次 hash 与发送时间戳；缺失或非法时分别返回 ""、0。回读会裁掉所有尾部换行
// （Bash 用 `cat` 捕获，若不裁，Go 会误判为不同 hash 而每次重发）。
func (s *Store) ReadLast() (hash string, sentAt int64) {
	hashName, err := s.entryName(s.HashFile)
	if err != nil {
		return "", 0
	}
	timeName, err := s.entryName(s.TimeFile)
	if err != nil {
		return "", 0
	}
	directory, exists, err := s.openDirectory()
	if err != nil || !exists {
		return "", 0
	}
	defer directory.Close()
	if b, err := readStateFileAt(directory, hashName, 256, os.Geteuid()); err == nil {
		hash = strings.TrimRight(string(b), "\n")
	}
	if b, err := readStateFileAt(directory, timeName, 64, os.Geteuid()); err == nil {
		if n, err := strconv.ParseInt(strings.TrimRight(string(b), "\n"), 10, 64); err == nil {
			sentAt = n
		}
	}
	return hash, sentAt
}

func readStateFile(path string, limit int64, euid int) ([]byte, error) {
	directory, exists, err := filetrust.OpenExistingDirectory(filepath.Dir(path), euid)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, os.ErrNotExist
	}
	defer directory.Close()
	return readStateFileAt(directory, filepath.Base(path), limit, euid)
}

func readStateFileAt(directory *os.File, name string, limit int64, euid int) ([]byte, error) {
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := filetrust.ValidateRegular(info, euid, 0o022, false); err != nil {
		return nil, fmt.Errorf("unsafe state file %s: %w", name, err)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, io.ErrUnexpectedEOF
	}
	return b, nil
}

// Write 用临时文件 + rename 写状态。时间戳先提交、hash 后提交：若第二次 rename 失败，旧 hash
// 仍与当前告警不匹配，下一轮会重发而不会被新时间戳静默抑制。调用方仍会收到错误。
func (s *Store) Write(hash string, now int64) error {
	hashName, err := s.entryName(s.HashFile)
	if err != nil {
		return err
	}
	timeName, err := s.entryName(s.TimeFile)
	if err != nil {
		return err
	}
	directory, exists, err := s.openDirectory()
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("state directory does not exist: %s", s.Dir)
	}
	defer directory.Close()
	return s.writeAlertAt(directory, hashName, timeName, hash, now)
}

// WriteDelivery records a successful channel delivery. The identity-free
// pending marker is committed first and removed last. Thus every error or crash
// between the target, timestamp, and hash commits leaves evidence that forces a
// retry instead of silently suppressing a message to a newly selected target.
func (s *Store) WriteDelivery(hash string, now int64, targetFingerprint string) error {
	if !validFingerprint(targetFingerprint) {
		return fmt.Errorf("invalid delivery target fingerprint")
	}
	hashName, err := s.entryName(s.HashFile)
	if err != nil {
		return err
	}
	timeName, err := s.entryName(s.TimeFile)
	if err != nil {
		return err
	}
	targetName, err := s.entryName(s.TargetFile)
	if err != nil {
		return err
	}
	pendingName, err := s.entryName(s.TargetPendingFile)
	if err != nil {
		return err
	}
	directory, exists, err := s.openDirectory()
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("state directory does not exist: %s", s.Dir)
	}
	defer directory.Close()
	if err := s.atomicAt(directory, pendingName, "pending\n"); err != nil {
		return fmt.Errorf("commit delivery target pending marker: %w", err)
	}
	if err := s.atomicAt(directory, targetName, targetFingerprint+"\n"); err != nil {
		return fmt.Errorf("commit delivery target fingerprint: %w", err)
	}
	if err := s.writeAlertAt(directory, hashName, timeName, hash, now); err != nil {
		return err
	}
	if err := syscall.Unlinkat(int(directory.Fd()), pendingName); err != nil {
		return fmt.Errorf("clear delivery target pending marker: %w", err)
	}
	if err := s.syncDirectory(directory); err != nil {
		return fmt.Errorf("sync state directory after clearing delivery target pending marker: %w", err)
	}
	return nil
}

func (s *Store) writeAlertAt(directory *os.File, hashName, timeName, hash string, now int64) error {
	if err := s.atomicAt(directory, timeName, strconv.FormatInt(now, 10)+"\n"); err != nil {
		return err
	}
	return s.atomicAt(directory, hashName, hash+"\n")
}

func (s *Store) atomicAt(directory *os.File, destination, content string) error {
	procPath := filepath.Join("/proc/self/fd", strconv.Itoa(int(directory.Fd())))
	tmp, err := os.CreateTemp(procPath, ".state.*")
	if err != nil {
		return err
	}
	tmpName := filepath.Base(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		_ = syscall.Unlinkat(int(directory.Fd()), tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = syscall.Unlinkat(int(directory.Fd()), tmpName)
		return err
	}
	if err := s.syncFile(tmp); err != nil {
		_ = tmp.Close()
		_ = syscall.Unlinkat(int(directory.Fd()), tmpName)
		return fmt.Errorf("sync state temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = syscall.Unlinkat(int(directory.Fd()), tmpName)
		return err
	}
	if err := syscall.Renameat(int(directory.Fd()), tmpName, int(directory.Fd()), destination); err != nil {
		_ = syscall.Unlinkat(int(directory.Fd()), tmpName)
		return err
	}
	if err := s.syncDirectory(directory); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

func (s *Store) syncFile(file *os.File) error {
	if s.fileSync != nil {
		return s.fileSync(file)
	}
	return file.Sync()
}

func (s *Store) syncDirectory(directory *os.File) error {
	if s.directorySync != nil {
		return s.directorySync(directory)
	}
	return directory.Sync()
}

func (s *Store) entryName(path string) (string, error) {
	if s.Dir == "" || path == "" || filepath.Clean(filepath.Dir(path)) != filepath.Clean(s.Dir) {
		return "", fmt.Errorf("state file %q is outside state directory %q", path, s.Dir)
	}
	name := filepath.Base(path)
	if name == "." || name == ".." || strings.ContainsAny(name, `/\\`) {
		return "", fmt.Errorf("invalid state file name %q", name)
	}
	return name, nil
}

func (s *Store) openDirectory() (*os.File, bool, error) {
	directory, exists, err := filetrust.OpenExistingDirectory(s.Dir, os.Geteuid())
	if err == nil && exists && s.afterDirectoryOpen != nil {
		s.afterDirectoryOpen()
	}
	return directory, exists, err
}
