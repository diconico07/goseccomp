// SPDX-Licence-Identifier: MIT

package goseccomp

import (
	"github.com/diconico07/goseccomp/lowlevel"
	"golang.org/x/net/bpf"
)

type DecisionType uint32

const (
	Allow       DecisionType = lowlevel.SECCOMP_RET_ALLOW
	KillProcess DecisionType = lowlevel.SECCOMP_RET_KILL_PROCESS
	KillThread  DecisionType = lowlevel.SECCOMP_RET_KILL_THREAD
	Errno       DecisionType = lowlevel.SECCOMP_RET_ERRNO
	Trap        DecisionType = lowlevel.SECCOMP_RET_TRAP
	Trace       DecisionType = lowlevel.SECCOMP_RET_TRACE
	Log         DecisionType = lowlevel.SECCOMP_RET_LOG
	UserNotify  DecisionType = lowlevel.SECCOMP_RET_USER_NOTIF
)

// Decision represent an outcome of the BPF seccomp filter
type Decision struct {
	// Type is one of the allowed return code for a BPF seccomp filter
	Type DecisionType
	// Data is the arbitrary data that can accompany some of the decisions
	Data uint16
}

// ToUint32 converts the Decision into an integer suitable for BPF return value
func (d Decision) ToUint32() uint32 {
	return uint32(d.Type) | uint32(d.Data)
}

func (d Decision) compile() bpf.RetConstant {
	return bpf.RetConstant{Val: d.ToUint32()}
}
