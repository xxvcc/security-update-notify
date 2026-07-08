// Package lock 用 flock 实现运行时的单实例互斥，复刻 `exec 9>LOCK_FILE; flock -n 9 || exit 0`：
// 非阻塞抢锁，抢不到（已有实例在跑）时返回 acquired=false，调用方据此静默退出 0。
//
// Package lock provides the runtime's single-instance mutex via flock, reproducing
// `exec 9>LOCK_FILE; flock -n 9 || exit 0`: a non-blocking acquire that returns acquired=false when
// another instance holds it, so the caller exits 0 silently.
package lock

import (
	"os"
	"syscall"
)

// Acquire 非阻塞地对 path 加独占 flock。成功返回 release（释放并关闭 fd）与 acquired=true；已被占用
// 返回 acquired=false（release 为 nil，err 为 nil）；其它错误经 err 返回。
func Acquire(path string) (release func(), acquired bool, err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, false, err
	}
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == syscall.EWOULDBLOCK {
		f.Close()
		return nil, false, nil
	}
	if err != nil {
		f.Close()
		return nil, false, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, true, nil
}
