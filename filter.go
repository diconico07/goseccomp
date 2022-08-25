// SPDX-Licence-Identifier: MIT
package goseccomp

import (
	"fmt"
	"runtime"

	"github.com/diconico07/goseccomp/lowlevel"
	"golang.org/x/net/bpf"
)

var CurrentArch string = runtime.GOARCH

type Filter struct {
	Elements        []FilterElement
	DefaultDecision Decision
	Architecture    string
}

func (f *Filter) mergeAllDuplicatesDecisions() {
	var newElements []FilterElement
OUTER:
	for _, filter := range f.Elements {
		for i, mFilter := range newElements {
			if filter.Decision == mFilter.Decision {
				newElements[i].Match = append(
					newElements[i].Match,
					filter.Match...,
				)
				continue OUTER
			}
		}
		newElements = append(newElements, filter)
	}
	f.Elements = newElements
}

func (f *Filter) mergeConsecutiveDuplicateDecisions() {
	var newElements []FilterElement
	for _, filter := range f.Elements {
		if len(newElements) != 0 {
			if filter.Decision == newElements[len(newElements)-1].Decision {
				newElements[len(newElements)-1].Match = append(
					newElements[len(newElements)-1].Match,
					filter.Match...,
				)
				continue
			}
		}
		newElements = append(newElements, filter)
	}
	f.Elements = newElements
}

func (f *Filter) splitOrderElements() {
	var lastOrderedFilter int = 0
OUTER:
	for {
		for x, filter := range f.Elements[lastOrderedFilter:] {
			for i, element := range filter.Match {
				bestPosition := 0
				for j, mFilter := range f.Elements[lastOrderedFilter:] {
					for _, mElement := range mFilter.Match {
						if element.Match(mElement) {
							if !element.IsMorePrecise(mElement) {
								bestPosition = j + 1
							}
						}
					}
				}
				if bestPosition != 0 {
					newFilter := FilterElement{
						Match: []SyscallCallFilter{
							element,
						},
						Decision: filter.Decision,
					}
					f.Elements[x].Match = append(
						f.Elements[x].Match[:i],
						f.Elements[x].Match[i+1:]...,
					)
					if bestPosition == len(f.Elements) {
						f.Elements = append(f.Elements, newFilter)
					} else {
						f.Elements = append(
							f.Elements[:bestPosition+1],
							f.Elements[bestPosition:]...,
						)
						f.Elements[bestPosition] = newFilter
					}
					continue OUTER
				}
			}
			lastOrderedFilter++
		}
		break
	}
}

func (f *Filter) Optimize() {
	f.mergeAllDuplicatesDecisions()
	f.splitOrderElements()
	f.mergeConsecutiveDuplicateDecisions()

	for x := range f.Elements {
		f.Elements[x].keepLeastPreciseMatch()
	}

}

func (f *Filter) Compile() ([]bpf.RawInstruction, error) {
	if !lowlevel.SeccompGetActionAvail(uint(f.DefaultDecision.Type)) {
		return nil, fmt.Errorf(
			"action '%v' unavailable",
			f.DefaultDecision.Type,
		)
	}
	for _, filter := range f.Elements {
		if !lowlevel.SeccompGetActionAvail(uint(filter.Decision.Type)) {
			return nil, fmt.Errorf(
				"action '%v' unavailable",
				filter.Decision.Type,
			)
		}
	}
	// Need to drop the redundant filters and order conflicting ones
	bpfProg := []bpf.Instruction{
		lowlevel.LoadSeccompDataField("Arch", false, f.Architecture),
		bpf.JumpIf{
			Cond:     bpf.JumpEqual,
			SkipTrue: 1,
			Val:      lowlevel.GetAuditArch(f.Architecture),
		},
		bpf.RetConstant{Val: lowlevel.SECCOMP_RET_KILL_PROCESS},
		lowlevel.LoadSeccompDataField("Number", false, f.Architecture),
	}
	for _, filter := range f.Elements {
		bpfProg = append(bpfProg, filter.compile(f.Architecture)...)
	}
	bpfProg = append(
		bpfProg,
		f.DefaultDecision.compile(),
	)

	rawBpf, err := bpf.Assemble(bpfProg)
	if err != nil {
		return nil, err
	}
	return rawBpf, nil
}

func (f *Filter) Insert() error {
	err := lowlevel.NoNewPrivs()
	if err != nil {
		return err
	}
	var flags uint
	for _, filter := range f.Elements {
		if filter.Decision.Type == UserNotify {
			flags |= lowlevel.SECCOMP_FILTER_FLAG_NEW_LISTENER
		}
	}
	compiled, err := f.Compile()
	if err != nil {
		return err
	}
	// TODO: Handle file descriptor when using new listener
	_, err = lowlevel.SeccompSetModeFilter(compiled, flags)
	if err != nil {
		return err
	}

	return nil
}
