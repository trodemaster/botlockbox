//go:build linux

package main

import "golang.org/x/sys/unix"

func applyHardening() {
	unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)
	unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}
