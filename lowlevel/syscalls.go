// SPDX-Licence-Identifier: MIT
package lowlevel

import (
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	SECCOMP_SET_MODE_STRICT  = 0
	SECCOMP_SET_MODE_FILTER  = 1
	SECCOMP_GET_ACTION_AVAIL = 2
	SECCOMP_GET_NOTIF_SIZES  = 3

	SECCOMP_RET_KILL_PROCESS = 0x80000000
	SECCOMP_RET_KILL_THREAD  = 0x00000000
	SECCOMP_RET_KILL         = SECCOMP_RET_KILL_THREAD
	SECCOMP_RET_TRAP         = 0x00030000
	SECCOMP_RET_ERRNO        = 0x00050000
	SECCOMP_RET_USER_NOTIF   = 0x7fc00000
	SECCOMP_RET_TRACE        = 0x7ff00000
	SECCOMP_RET_LOG          = 0x7ffc0000
	SECCOMP_RET_ALLOW        = 0x7fff0000

	SECCOMP_FILTER_FLAG_TSYNC              = 1 << 0
	SECCOMP_FILTER_FLAG_LOG                = 1 << 1
	SECCOMP_FILTER_FLAG_SPEC_ALLOW         = 1 << 2
	SECCOMP_FILTER_FLAG_NEW_LISTENER       = 1 << 3
	SECCOMP_FILTER_FLAG_TSYNC_ESRCH        = 1 << 4
	SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV = 1 << 5
)

type SeccompNotifSizes struct {
	SeccompNotif     uint16
	SeccompNotifResp uint16
	SeccompData      uint16
}

type seccompData struct {
	Number                             int32
	Arch                               uint32
	InstructionPointer                 uint64
	Arg0, Arg1, Arg2, Arg3, Arg4, Arg5 uint64
}

func LoadSeccompDataField(field string, highByte bool, arch string) bpf.LoadAbsolute {
	data := seccompData{}
	_ = data
	var offset uintptr
	switch field {
	case "Number":
		offset = unsafe.Offsetof(data.Number)
		highByte = false
	case "Arch":
		offset = unsafe.Offsetof(data.Arch)
		highByte = false
	case "InstructionPointer":
		offset = unsafe.Offsetof(data.InstructionPointer)
	case "Arg0":
		offset = unsafe.Offsetof(data.Arg0)
	case "Arg1":
		offset = unsafe.Offsetof(data.Arg1)
	case "Arg2":
		offset = unsafe.Offsetof(data.Arg2)
	case "Arg3":
		offset = unsafe.Offsetof(data.Arg3)
	case "Arg4":
		offset = unsafe.Offsetof(data.Arg4)
	case "Arg5":
		offset = unsafe.Offsetof(data.Arg5)
	}
	if ArchIsLittleEndian(arch) == highByte {
		offset += 4
	}
	return bpf.LoadAbsolute{
		Off:  uint32(offset),
		Size: 4,
	}
}

type sockFprog struct {
	len    uint16
	filter uintptr
}

func errnoErr(errno unix.Errno) error {
	switch errno {
	case 0:
		return nil
	default:
		return errno
	}
}

func seccomp(operation uint, flags uint, args uintptr) (int, unix.Errno) {
	ret, _, err := unix.Syscall(unix.SYS_SECCOMP, uintptr(operation), uintptr(flags), args)
	return int(ret), err
}

func SeccompGetActionAvail(return_action uint) bool {
	ret, _ := seccomp(SECCOMP_GET_ACTION_AVAIL, 0, uintptr(unsafe.Pointer(&return_action)))
	return ret == 0
}

func SeccompGetNotifSizes() (SeccompNotifSizes, error) {
	var sizes SeccompNotifSizes
	_, errno := seccomp(SECCOMP_GET_NOTIF_SIZES, 0, uintptr(unsafe.Pointer(&sizes)))
	return sizes, errnoErr(errno)
}

func SeccompSetModeFilter(prog []bpf.RawInstruction, flags uint) (int, error) {
	sock_prog := sockFprog{
		len:    uint16(len(prog)),
		filter: uintptr(unsafe.Pointer(&prog[0])),
	}
	ret, errno := seccomp(SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(&sock_prog)))
	if (flags&SECCOMP_FILTER_FLAG_NEW_LISTENER != 0) && ret >= 0 {
		return ret, nil
	}
	if ret != 0 {
		return 0, errnoErr(errno)
	}
	return 0, nil
}

func NoNewPrivs() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}
