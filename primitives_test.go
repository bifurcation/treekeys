package treekeys

import (
	"testing"
)

func TestDH(t *testing.T) {
	privA := DHKeyGen()
	privB := DHKeyGen()
	privC := DHKeyGen()

	gAB := Exp(PK(privA), privB)
	gBA := Exp(PK(privB), privA)
	if gAB != gBA {
		t.Fatalf("gAB != gBA")
	}

	// XXX: Should we have a better test of ι?  Does it matter?
	kAB := ι(gAB)
	kBA := ι(gBA)
	gABC := Exp(PK(privC), kAB)
	gBAC := Exp(PK(privC), kBA)
	if gABC != gBAC {
		t.Fatalf("gABC != gBAC")
	}
}
