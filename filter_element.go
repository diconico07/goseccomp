// SPDX-Licence-Identifier: MIT
package goseccomp

import "golang.org/x/net/bpf"

type FilterElement struct {
	Match    []SyscallCallFilter
	Decision Decision
}

func (f *FilterElement) compile(arch string) []bpf.Instruction {
	if len(f.Match) == 0 {
		return nil
	}
	var distanceToDecision uint = 0
	instructions := []bpf.Instruction{
		f.Decision.compile(),
	}
	for _, syscall := range f.Match {
		var distanceToNext uint = 0
		if distanceToDecision == 0 {
			distanceToNext = 1
		}
		newInstructions := syscall.compile(distanceToDecision, distanceToNext, arch)
		distanceToDecision += uint(len(newInstructions))
		instructions = append(newInstructions, instructions...)
	}
	return instructions
}

func (f *FilterElement) keepLeastPreciseMatch() {
	var newMatch []SyscallCallFilter
OUTER:
	for _, filter := range f.Match {
		for i, mFilter := range newMatch {
			if filter.Match(mFilter) {
				if mFilter.IsMorePrecise(filter) {
					newMatch[i] = filter
				}
				continue OUTER
			}
		}
		newMatch = append(newMatch, filter)
	}
	f.Match = newMatch
}
