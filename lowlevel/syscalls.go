// SPDX-Licence-Identifier: MIT

// This package allow syscall level interactions with the seccomp
// filter system. This package does almost no abstraction over
// the linux kernel API here, most of this is thus unsafe by nature.
package lowlevel

import (
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	// Seccomp syscall operation to set the current thread mode to strict
	SECCOMP_SET_MODE_STRICT = 0
	// Seccomp syscall operation to set the current thread mode to filter, and insert a filter
	SECCOMP_SET_MODE_FILTER = 1
	// Seccomp syscall operation to get whether a given filter action is available or not
	SECCOMP_GET_ACTION_AVAIL = 2
	// Seccomp syscall operation to get the sizes of the user-space notification structures
	SECCOMP_GET_NOTIF_SIZES = 3

	// Seccomp return action to terminate the process with a core dump. The syscall is not
	// executed, to the parent process it will seems as if the process received a SIGSYS signal
	SECCOMP_RET_KILL_PROCESS = 0x80000000
	// Seccomp return action to terminate the thread. The syscall is not executed, the thread get seemingly
	// killed by a SIGSYS signal
	SECCOMP_RET_KILL_THREAD = 0x00000000
	SECCOMP_RET_KILL        = SECCOMP_RET_KILL_THREAD
	// Seccomp return action to send a SIGSYS signal to the triggering thread. The syscall is not executed.
	SECCOMP_RET_TRAP = 0x00030000
	// Seccomp return action to return a given errno to the caller. The syscall is not executed.
	SECCOMP_RET_ERRNO = 0x00050000
	// Seccomp return action to forward the syscall to an attached user-space supervisor process. If there is no
	// attached process, the filter returns with ENOSYS
	SECCOMP_RET_USER_NOTIF = 0x7fc00000
	// Seccomp return action to trigger a ptrace notification. The syscall is not executed.
	SECCOMP_RET_TRACE = 0x7ff00000
	// Seccomp return action to log the syscall. The syscall is executed
	SECCOMP_RET_LOG = 0x7ffc0000
	// Seccomp return action to execute the syscall
	SECCOMP_RET_ALLOW = 0x7fff0000

	// Seccomp syscall filter mode flag to synchronize all threads to the same filter tree.
	// If any thread cannot synchronize, the syscall will fail and return the thread id
	// of the first non synced thread.
	SECCOMP_FILTER_FLAG_TSYNC = 1 << 0
	// Seccomp syscall filter mode flag to log all non-allow actions
	SECCOMP_FILTER_FLAG_LOG = 1 << 1
	// Seccomp syscall filter mode flag to disable speculative store bypass mitigation
	SECCOMP_FILTER_FLAG_SPEC_ALLOW = 1 << 2
	// Seccomp syscall filter mode flag to get a user-space notification file descriptor.
	// The file descriptor will have the close-on-exec flag set.
	SECCOMP_FILTER_FLAG_NEW_LISTENER = 1 << 3
	// Seccomp syscall filter mode flag similar to [SECCOMP_FILTER_FLAG_TSYNC], at the difference it will
	// return -ESRCH on failure
	SECCOMP_FILTER_FLAG_TSYNC_ESRCH = 1 << 4
	// Seccomp syscall filter mode flag to put the notifying process in killable state once the notification
	// is received by the user-space listener
	SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV = 1 << 5
)

// SeccompNotifSizes stores the sizes of the seccomp user-space notifications as returned by [SeccompGetNotifSizes]
type SeccompNotifSizes struct {
	// SeccompNotif stores the size of the notification structure
	SeccompNotif uint16
	// SeccompNotif stores the size of the response structure
	SeccompNotifResp uint16
	// SeccompData stores the size of the seccomp_data structure
	SeccompData uint16
}

type seccompData struct {
	Number                             int32
	Arch                               uint32
	InstructionPointer                 uint64
	Arg0, Arg1, Arg2, Arg3, Arg4, Arg5 uint64
}

// LoadSeccompDataField generates the [bpf.LoadAbsolute] instruction to access the given field
// in the seccomp data available to the bfp program.
// field must be one of "Number", "Arch", "InstructionPointer" or "ArgX" (with "X" from 0 to 5).
//
// On 64bits architectures setting highByte to true will fetch the most significant byte of the field
// (only relevant for "InstructionPointer" and "ArgX" fields)
//
// arch must be set to the target architecture of the filter and is used to use the right endianess
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

// SeccompGetActionAvail returns wether an action is supported by the kernel.
// This allows to confirm that the kernel knows of a recently added filter return action.
//
// As a reminder, the kernel treats all unknown actions as SECCOMP_RET_KILL_PROCESS action.
func SeccompGetActionAvail(return_action uint) bool {
	ret, _ := seccomp(SECCOMP_GET_ACTION_AVAIL, 0, uintptr(unsafe.Pointer(&return_action)))
	return ret == 0
}

// SeccompGetNotifSizes retrieve the sizes of the seccomp user-space notification structures.
func SeccompGetNotifSizes() (SeccompNotifSizes, error) {
	var sizes SeccompNotifSizes
	_, errno := seccomp(SECCOMP_GET_NOTIF_SIZES, 0, uintptr(unsafe.Pointer(&sizes)))
	return sizes, errnoErr(errno)
}

// SeccompSetModeFilter is a wrapper to the "seccomp" syscall, it sets the current
// thread seccomp mode to "filter" and inserts the given filter a the top of the
// seccomp filters stack of the thread.
// flags can be set to any valid combination of the "SECCOMP_FLAG_*" constants.
//
// SeccompSetModeFilter returns the file descriptor returned by the syscall if
// SECCOMP_FILTER_FLAG_NEW_LISTENER is set and an error.
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

// NoNewPrivs is a simple wrapper to [unix.Prctl] to set the "No New Privs" bit on the current
// thread.
// This is needed in order to load a seccomp filter as a non privileged user.
func NoNewPrivs() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}
