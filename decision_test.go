// SPDX-Licence-Identifier: MIT
package goseccomp

import "testing"

func TestDecisionToUint32(t *testing.T) {
	decision := Decision{
		Type: KillThread,
		Data: 0x42,
	}
	uintDecision := decision.ToUint32()
	if uintDecision != 0x42 {
		t.Errorf("Uint decision should be 0x42 got 0x%x", uintDecision)
	}
	decision.Type = KillProcess
	uintDecision = decision.ToUint32()
	if uintDecision != 0x80000042 {
		t.Errorf("Uint decision should be 0x42 got 0x%x", uintDecision)
	}

}

func TestDecisionCompile(t *testing.T) {
	decision := Decision{Type: KillThread, Data: 0}

	ret := decision.compile()
	if ret.String() != "ret #0" {
		t.Errorf(
			"decision compile failed excpected '%s', got '%s'",
			"ret #0",
			ret.String(),
		)
	}
}
