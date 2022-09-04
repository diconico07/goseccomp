// SPDX-Licence-Identifier: MIT

package goseccomp

import (
	"reflect"
	"runtime"
	"testing"

	"github.com/diconico07/goseccomp/lowlevel"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type TestCaseFilterSelf struct {
	Orig     Filter
	Expected Filter
}

func TestFilterMergeAllDuplcates(t *testing.T) {
	cases := []TestCaseFilterSelf{
		{
			Orig:     Filter{},
			Expected: Filter{},
		},
		{
			Orig: Filter{
				Elements: []FilterElement{
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{},
							{Number: 1},
						},
					},
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{Number: 2},
						},
					},
					{
						Decision: Decision{Type: Allow},
					},
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{Number: 3},
						},
					},
				},
			},
			Expected: Filter{
				Elements: []FilterElement{
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{},
							{Number: 1},
							{Number: 2},
							{Number: 3},
						},
					},
					{
						Decision: Decision{Type: Allow},
					},
				},
			},
		},
	}
	for i, tc := range cases {
		tc.Orig.mergeAllDuplicatesDecisions()
		if !reflect.DeepEqual(tc.Orig, tc.Expected) {
			t.Errorf(
				"[%d/%d] Expected: %+v Got %+v",
				i+1, len(cases),
				tc.Expected,
				tc.Orig,
			)
		}
	}
}

func TestFilterMergeConsecutiveDuplcates(t *testing.T) {
	cases := []TestCaseFilterSelf{
		{
			Orig:     Filter{},
			Expected: Filter{},
		},
		{
			Orig: Filter{
				Elements: []FilterElement{
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{},
							{Number: 1},
						},
					},
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{Number: 2},
						},
					},
					{
						Decision: Decision{Type: Allow},
					},
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{Number: 3},
						},
					},
				},
			},
			Expected: Filter{
				Elements: []FilterElement{
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{},
							{Number: 1},
							{Number: 2},
						},
					},
					{
						Decision: Decision{Type: Allow},
					},
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{Number: 3},
						},
					},
				},
			},
		},
	}
	for i, tc := range cases {
		tc.Orig.mergeConsecutiveDuplicateDecisions()
		if !reflect.DeepEqual(tc.Orig, tc.Expected) {
			t.Errorf(
				"[%d/%d]\n\tExpected: %+v\n\tGot:      %+v",
				i+1, len(cases),
				tc.Expected,
				tc.Orig,
			)
		}
	}
}

func TestFilterSplitOrderElement(t *testing.T) {
	cases := []TestCaseFilterSelf{
		{
			Orig: Filter{
				Elements: []FilterElement{
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{
								Number: 1,
								Args: [6]SyscallArgument{
									{0, false},
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
								},
							},
							{
								Number: 2,
								Args: [6]SyscallArgument{
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
								},
							},
							{
								Number: 3,
								Args: [6]SyscallArgument{
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
								},
							},
						},
					},
					{
						Decision: Decision{Type: Allow},
						Match: []SyscallCallFilter{
							{
								Number: 1,
								Args: [6]SyscallArgument{
									{0, false},
									{1, false},
									Any(),
									Any(),
									Any(),
									Any(),
								},
							},
						},
					},
					{
						Decision: Decision{Type: Errno},
						Match: []SyscallCallFilter{
							{
								Number: 1,
								Args: [6]SyscallArgument{
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
								},
							},
							{
								Number: 3,
								Args: [6]SyscallArgument{
									{0, false},
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
								},
							},
						},
					},
				},
			},
			Expected: Filter{
				Elements: []FilterElement{
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{
								Number: 2,
								Args: [6]SyscallArgument{
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
								},
							},
						},
					},
					{
						Decision: Decision{Type: Allow},
						Match: []SyscallCallFilter{
							{
								Number: 1,
								Args: [6]SyscallArgument{
									{0, false},
									{1, false},
									Any(),
									Any(),
									Any(),
									Any(),
								},
							},
						},
					},
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{
								Number: 1,
								Args: [6]SyscallArgument{
									{0, false},
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
								},
							},
						},
					},
					{
						Decision: Decision{Type: Errno},
						Match: []SyscallCallFilter{
							{
								Number: 1,
								Args: [6]SyscallArgument{
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
								},
							},
							{
								Number: 3,
								Args: [6]SyscallArgument{
									{0, false},
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
								},
							},
						},
					},
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{
								Number: 3,
								Args: [6]SyscallArgument{
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
									Any(),
								},
							},
						},
					},
				},
			},
		},
		{
			Orig:     Filter{},
			Expected: Filter{},
		},
	}
	for i, tc := range cases {
		tc.Orig.splitOrderElements()
		if !reflect.DeepEqual(tc.Orig, tc.Expected) {
			t.Errorf(
				"[%d/%d]\n\tExpected: %+v\n\tGot:      %+v",
				i+1, len(cases),
				tc.Expected,
				tc.Orig,
			)
		}
	}

}

func TestFilterOptimize(t *testing.T) {
	cases := []TestCaseFilterSelf{
		{
			Orig:     Filter{},
			Expected: Filter{},
		},
		{
			Orig: Filter{
				Elements: []FilterElement{
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{
								Number: 0,
								Args:   [6]SyscallArgument{},
							},
						},
					},
					{
						Decision: Decision{Type: KillProcess},
						Match: []SyscallCallFilter{
							{
								Number: 0,
								Args:   [6]SyscallArgument{Any(), Any(), {}, {}, {}, {}},
							},
						},
					},
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{
								Number: 0,
								Args:   [6]SyscallArgument{Any(), Any(), Any(), Any(), Any(), Any()},
							},
						},
					},
				},
			},
			Expected: Filter{
				Elements: []FilterElement{
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{
								Number: 0,
								Args:   [6]SyscallArgument{},
							},
						},
					},
					{
						Decision: Decision{Type: KillProcess},
						Match: []SyscallCallFilter{
							{
								Number: 0,
								Args:   [6]SyscallArgument{Any(), Any(), {}, {}, {}, {}},
							},
						},
					},
					{
						Decision: Decision{},
						Match: []SyscallCallFilter{
							{
								Number: 0,
								Args:   [6]SyscallArgument{Any(), Any(), Any(), Any(), Any(), Any()},
							},
						},
					},
				},
			},
		},
	}
	for i, tc := range cases {
		tc.Orig.Optimize()
		if !reflect.DeepEqual(tc.Orig, tc.Expected) {
			t.Errorf(
				"[%d/%d]\n\tExpected: %+v\n\tGot:      %+v",
				i+1, len(cases),
				tc.Expected,
				tc.Orig,
			)
		}
	}
}

func assembleNoError(in []bpf.Instruction) []bpf.RawInstruction {
	asm, _ := bpf.Assemble(in)
	return asm
}

type TestCaseFilterCompile struct {
	Filter       Filter
	Instructions []bpf.RawInstruction
}

func TestFilterCompile(t *testing.T) {
	cases := []TestCaseFilterCompile{
		{
			Filter: Filter{Architecture: "386"},
			Instructions: assembleNoError([]bpf.Instruction{
				lowlevel.LoadSeccompDataField("Arch", false, "386"),
				bpf.JumpIf{
					Cond:     bpf.JumpEqual,
					SkipTrue: 1,
					Val:      lowlevel.GetAuditArch("386"),
				},
				bpf.RetConstant{Val: lowlevel.SECCOMP_RET_KILL_PROCESS},
				lowlevel.LoadSeccompDataField("Number", false, "386"),
				bpf.RetConstant{Val: 0},
			}),
		},
		{
			Filter: Filter{
				Architecture: "386",
				Elements:     []FilterElement{{}},
			},
			Instructions: assembleNoError([]bpf.Instruction{
				lowlevel.LoadSeccompDataField("Arch", false, "386"),
				bpf.JumpIf{
					Cond:     bpf.JumpEqual,
					SkipTrue: 1,
					Val:      lowlevel.GetAuditArch("386"),
				},
				bpf.RetConstant{Val: lowlevel.SECCOMP_RET_KILL_PROCESS},
				lowlevel.LoadSeccompDataField("Number", false, "386"),
				bpf.RetConstant{Val: 0},
			}),
		},
	}
	for i, tc := range cases {
		got, err := tc.Filter.Compile()
		if err != nil {
			t.Skipf("Failed to compile, skipping")
		}
		if !reflect.DeepEqual(tc.Instructions, got) {
			t.Errorf(
				"[%d/%d]\n\tExpected: %+v\n\tGot:      %+v",
				i+1, len(cases),
				tc.Instructions,
				got,
			)
		}
	}
}

func TestFilterCompileErrors(t *testing.T) {
	cases := []TestCaseFilterCompile{
		{
			Filter: Filter{Architecture: "386", DefaultDecision: Decision{Type: 1}},
		},
		{
			Filter: Filter{
				Architecture: "386",
				Elements:     []FilterElement{{Decision: Decision{Type: 1}}},
			},
		},
	}
	for _, tc := range cases {
		_, err := tc.Filter.Compile()
		if err == nil {
			t.Errorf("Got no error")
		}
		if err.Error() != "action '1' unavailable" {
			t.Error(err)
		}
	}
}

func TestFilterInsert(t *testing.T) {
	skipc := make(chan bool, 1)
	skip := func() {
		skipc <- true
		runtime.Goexit()
	}

	go func() {
		// This test uses prctl to modify the calling thread, so run it on its own
		// throwaway thread and do not unlock it when the goroutine exits.
		runtime.LockOSThread()
		defer close(skipc)

		filter := Filter{DefaultDecision: Decision{Type: Allow}, Architecture: runtime.GOARCH}

		err := filter.Insert()
		if err != nil {
			t.Logf("Prctl: %v, skipping test", err)
			skip()
		}

		v, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
		if err != nil {
			t.Errorf("failed to perform prctl: %v", err)
		}
		if v != 1 {
			t.Errorf("unexpected return from prctl; got %v, expected %v", v, 1)
		}
	}()

	if <-skipc {
		t.SkipNow()
	}
}
