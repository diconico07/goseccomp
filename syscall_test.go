// SPDX-Licence-Identifier: MIT

package goseccomp

import (
	"reflect"
	"testing"

	"github.com/diconico07/goseccomp/lowlevel"
	"golang.org/x/net/bpf"
)

type TestCasesSyscallComparisons struct {
	arg1     SyscallCallFilter
	arg2     SyscallCallFilter
	expected bool
}

func TestSyscallMatch(t *testing.T) {
	cases := []TestCasesSyscallComparisons{
		{
			SyscallCallFilter{
				Number: 0,
				Args: [6]SyscallArgument{
					{0, false},
					{1, false},
					{2, false},
					{3, false},
					{4, false},
					{5, false},
				},
			},
			SyscallCallFilter{},
			false,
		},
		{
			SyscallCallFilter{},
			SyscallCallFilter{},
			true,
		},
		{
			SyscallCallFilter{},
			SyscallCallFilter{
				Number: 0,
				Args: [6]SyscallArgument{
					{0, false},
					{1, true},
					{2, true},
					{3, true},
					{4, true},
					{5, true},
				},
			},
			true,
		},
		{
			SyscallCallFilter{
				Number: 0,
				Args: [6]SyscallArgument{
					{0, false},
					{1, true},
					{2, true},
					{3, true},
					{4, true},
					{5, true},
				},
			},
			SyscallCallFilter{},
			true,
		},
		{
			SyscallCallFilter{Number: 1},
			SyscallCallFilter{},
			false,
		},
	}
	for _, tc := range cases {
		got := tc.arg1.Match(tc.arg2)
		if tc.expected != got {
			t.Errorf("Expected '%t' got '%t'", tc.expected, got)
		}
	}
}

func TestSyscallIsMorePrecise(t *testing.T) {
	cases := []TestCasesSyscallComparisons{
		{
			SyscallCallFilter{},
			SyscallCallFilter{},
			true,
		},
		{
			SyscallCallFilter{
				Args: [6]SyscallArgument{
					{0, false},
					{1, true},
					{2, true},
					{3, true},
					{4, true},
					{5, true},
				},
			},
			SyscallCallFilter{},
			false,
		},
		{
			SyscallCallFilter{},
			SyscallCallFilter{
				Args: [6]SyscallArgument{
					{0, false},
					{1, true},
					{2, true},
					{3, true},
					{4, true},
					{5, true},
				},
			},
			true,
		},
	}
	for _, tc := range cases {
		got := tc.arg1.IsMorePrecise(tc.arg2)
		if tc.expected != got {
			t.Errorf("Expected '%t' got '%t'", tc.expected, got)
		}
	}
}

type TestCasesSycallCompile struct {
	arg      SyscallCallFilter
	dok      uint
	dnok     uint
	arch     string
	expected []bpf.Instruction
}

func TestSyscallCompile(t *testing.T) {
	cases := []TestCasesSycallCompile{
		{
			SyscallCallFilter{},
			0,
			0,
			"386",
			nil,
		},
		{
			SyscallCallFilter{
				Args: [6]SyscallArgument{
					{1, false},
					{2, false},
					{3, false},
					{4, false},
					{5, false},
					{6, false},
				},
			},
			1,
			0,
			"386",
			[]bpf.Instruction{
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 14, Val: 0},
				lowlevel.LoadSeccompDataField("Arg5", false, "386"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 12, Val: 6},
				lowlevel.LoadSeccompDataField("Arg4", false, "386"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 10, Val: 5},
				lowlevel.LoadSeccompDataField("Arg3", false, "386"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 8, Val: 4},
				lowlevel.LoadSeccompDataField("Arg2", false, "386"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 6, Val: 3},
				lowlevel.LoadSeccompDataField("Arg1", false, "386"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 4, Val: 2},
				lowlevel.LoadSeccompDataField("Arg0", false, "386"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 2, Val: 1},
				lowlevel.LoadSeccompDataField("Number", false, "386"),
				bpf.Jump{Skip: 1},
			},
		},
		{
			SyscallCallFilter{
				Args: [6]SyscallArgument{
					{0x200000001, false},
					{0x400000003, false},
					{0x600000005, false},
					{0x800000007, false},
					{0xa00000009, false},
					{0xc0000000b, false},
				},
			},
			1,
			0,
			"amd64",
			[]bpf.Instruction{
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 26, Val: 0},
				lowlevel.LoadSeccompDataField("Arg5", false, "amd64"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 24, Val: 11},
				lowlevel.LoadSeccompDataField("Arg5", true, "amd64"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 22, Val: 12},
				lowlevel.LoadSeccompDataField("Arg4", false, "amd64"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 20, Val: 9},
				lowlevel.LoadSeccompDataField("Arg4", true, "amd64"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 18, Val: 10},
				lowlevel.LoadSeccompDataField("Arg3", false, "amd64"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 16, Val: 7},
				lowlevel.LoadSeccompDataField("Arg3", true, "amd64"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 14, Val: 8},
				lowlevel.LoadSeccompDataField("Arg2", false, "amd64"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 12, Val: 5},
				lowlevel.LoadSeccompDataField("Arg2", true, "amd64"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 10, Val: 6},
				lowlevel.LoadSeccompDataField("Arg1", false, "amd64"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 8, Val: 3},
				lowlevel.LoadSeccompDataField("Arg1", true, "amd64"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 6, Val: 4},
				lowlevel.LoadSeccompDataField("Arg0", false, "amd64"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 4, Val: 1},
				lowlevel.LoadSeccompDataField("Arg0", true, "amd64"),
				bpf.JumpIf{Cond: bpf.JumpNotEqual, SkipTrue: 2, Val: 2},
				lowlevel.LoadSeccompDataField("Number", false, "amd64"),
				bpf.Jump{Skip: 1},
			},
		},
		{
			SyscallCallFilter{
				Args: [6]SyscallArgument{
					Any(),
					Any(),
					Any(),
					Any(),
					Any(),
					Any(),
				},
			},
			1,
			0,
			"386",
			[]bpf.Instruction{
				bpf.JumpIf{
					Cond:      bpf.JumpEqual,
					SkipTrue:  1,
					SkipFalse: 0,
				},
			},
		},
	}
	for i, tc := range cases {
		got := tc.arg.compile(tc.dok, tc.dnok, tc.arch)
		if !reflect.DeepEqual(got, tc.expected) {
			t.Errorf(
				"[%d/%d] Expected '%+v' got '%+v'",
				i+1, len(cases),
				tc.expected,
				got,
			)
		}
	}
}
