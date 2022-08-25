// SPDX-Licence-Identifier: MIT
package goseccomp

import (
	"fmt"

	"github.com/diconico07/goseccomp/lowlevel"
	"golang.org/x/net/bpf"
)

type SyscallArgument struct {
	Value uintptr
	isAny bool
}

func Any() SyscallArgument { return SyscallArgument{Value: 0, isAny: true} }

type SyscallCallFilter struct {
	Number uint
	Args   [6]SyscallArgument
}

func (a SyscallCallFilter) Match(b SyscallCallFilter) bool {
	if a.Number != b.Number {
		return false
	}
	for i, v := range a.Args {
		if v.isAny || b.Args[i].isAny {
			continue
		}
		if v.Value != b.Args[i].Value {
			return false
		}
	}
	return true
}

func (a SyscallCallFilter) IsMorePrecise(b SyscallCallFilter) bool {
	for i, v := range a.Args {
		if v.isAny && !b.Args[i].isAny {
			return false
		}
	}
	return true
}

func (a SyscallCallFilter) compile(distanceToMatch uint, distanceToNoMatch uint, arch string) []bpf.Instruction {
	if distanceToMatch == distanceToNoMatch {
		return nil
	}
	var instructions []bpf.Instruction
	/* We are constructing the instruction list from the end
	*  to the begining, so start with the arguments
	 */
	for i, arg := range a.Args {
		if !arg.isAny {
			argName := fmt.Sprintf("Arg%d", i)
			argInstructions := []bpf.Instruction{
				lowlevel.LoadSeccompDataField(argName, false, arch),
			}
			if len(instructions) == 0 {
				distanceToNoMatch += 2
			}
			if lowlevel.ArchIs64Bits(arch) {
				argInstructions = append(
					argInstructions,
					bpf.JumpIf{
						Cond:     bpf.JumpNotEqual,
						SkipTrue: uint8(distanceToNoMatch) + 2,
						Val:      uint32(arg.Value),
					},
					lowlevel.LoadSeccompDataField(argName, true, arch),
					bpf.JumpIf{
						Cond:     bpf.JumpNotEqual,
						SkipTrue: uint8(distanceToNoMatch),
						Val:      uint32(arg.Value >> 32),
					},
				)
			} else {
				argInstructions = append(
					argInstructions,
					bpf.JumpIf{
						Cond:     bpf.JumpNotEqual,
						SkipTrue: uint8(distanceToNoMatch),
						Val:      uint32(arg.Value),
					},
				)
			}
			if len(instructions) == 0 {
				distanceToNoMatch -= 2
				argInstructions = append(
					argInstructions,
					lowlevel.LoadSeccompDataField("Number", false, arch),
					bpf.Jump{Skip: uint32(distanceToMatch)},
				)
			}
			distanceToMatch += uint(len(argInstructions))
			distanceToNoMatch += uint(len(argInstructions))
			instructions = append(
				argInstructions,
				instructions...,
			)
		}
	}

	// Now let's prepend with syscall number check
	if len(instructions) == 0 {
		// All args checks were "Any"
		instructions = append(instructions, bpf.JumpIf{
			Cond:      bpf.JumpEqual,
			SkipTrue:  uint8(distanceToMatch),
			SkipFalse: uint8(distanceToNoMatch),
			Val:       uint32(a.Number),
		})
	} else {
		instructions = append(
			[]bpf.Instruction{
				bpf.JumpIf{
					Cond:     bpf.JumpNotEqual,
					SkipTrue: uint8(distanceToNoMatch),
					Val:      uint32(a.Number),
				},
			},
			instructions...,
		)
	}

	return instructions
}
