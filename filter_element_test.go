// SPDX-Licence-Identifier: MIT
package goseccomp

import (
	"reflect"
	"testing"

	"golang.org/x/net/bpf"
)

type TestCasesFilterElementKeep struct {
	Orig     FilterElement
	Expected FilterElement
}

func TestFilterElementKeepLeastPreciseMatch(t *testing.T) {
	cases := []TestCasesFilterElementKeep{
		{
			Orig:     FilterElement{},
			Expected: FilterElement{},
		},
		{
			Orig: FilterElement{
				Match: []SyscallCallFilter{
					{
						Args: [6]SyscallArgument{
							Any(), Any(), Any(), Any(), Any(), Any(),
						},
						Number: 0,
					},
					{
						Args: [6]SyscallArgument{
							{4, false}, Any(), Any(), Any(), Any(), Any(),
						},
						Number: 1,
					},
					{
						Args: [6]SyscallArgument{
							Any(), Any(), Any(), Any(), Any(), Any(),
						},
						Number: 1,
					},
					{
						Args: [6]SyscallArgument{
							Any(), {1, false}, Any(), Any(), Any(), Any(),
						},
						Number: 0,
					},
				},
			},
			Expected: FilterElement{
				Match: []SyscallCallFilter{
					{
						Args: [6]SyscallArgument{
							Any(), Any(), Any(), Any(), Any(), Any(),
						},
						Number: 0,
					},
					{
						Args: [6]SyscallArgument{
							Any(), Any(), Any(), Any(), Any(), Any(),
						},
						Number: 1,
					},
				},
			},
		},
	}
	for i, tc := range cases {
		tc.Orig.keepLeastPreciseMatch()

		if !reflect.DeepEqual(tc.Orig, tc.Expected) {
			t.Errorf(
				"[%d/%d] Expected: %+v Got: %+v",
				i+1, len(cases),
				tc.Expected,
				tc.Orig,
			)
		}
	}
}

type TestCasesFilterElementCompile struct {
	arch     string
	elem     FilterElement
	expected []bpf.Instruction
}

func TestFilterElementCompile(t *testing.T) {
	cases := []TestCasesFilterElementCompile{
		{
			arch:     "386",
			elem:     FilterElement{},
			expected: nil,
		},
		{
			arch: "386",
			elem: FilterElement{
				Decision: Decision{Type: KillThread, Data: 0},
				Match: []SyscallCallFilter{
					{0, [6]SyscallArgument{Any(), Any(), Any(), Any(), Any(), Any()}},
					{1, [6]SyscallArgument{Any(), Any(), Any(), Any(), Any(), Any()}},
				},
			},
			expected: []bpf.Instruction{
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1, SkipTrue: 1},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipFalse: 1},
				bpf.RetConstant{Val: 0},
			},
		},
	}
	for i, tc := range cases {
		got := tc.elem.compile(tc.arch)

		if !reflect.DeepEqual(got, tc.expected) {
			t.Errorf(
				"[%d/%d] Expected: %#v Got: %#v",
				i+1, len(cases),
				tc.expected,
				got,
			)
		}
	}
}
