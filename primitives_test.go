package treekeys

import (
	"encoding/json"
	"testing"
)

func TestGroupElementJSON(t *testing.T) {
	g := GroupElement{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37}

	gj, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("Marshal %v", err)
	}

	var g2 GroupElement
	err = json.Unmarshal(gj, &g2)
	if err != nil {
		t.Fatalf("Unmarshal %v", err)
	}

	if g != g2 {
		t.Fatalf("Mismatch [%x] != [%x]", g, g2)
	}
}

func TestMAC(t *testing.T) {
	key := []byte{0, 1, 2, 3}
	msg := []byte{4, 5, 6, 7}
	mac := MAC(key, msg)
	ver := VerifyMAC(key, msg, mac)
	if !ver {
		t.Fatalf("Verify failure")
	}
}

func TestDH(t *testing.T) {
	privA := DHKeyGen()
	privB := DHKeyGen()
	privC := DHKeyGen()

	gAB := Exp(PK(privA), privB)
	gBA := Exp(PK(privB), privA)
	if gAB != gBA {
		t.Fatalf("gAB != gBA")
	}

	// Should we have a better test of ι?  Does it matter?
	kAB := ι(gAB)
	kBA := ι(gBA)
	gABC := Exp(PK(privC), kAB)
	gBAC := Exp(PK(privC), kBA)
	if gABC != gBAC {
		t.Fatalf("gABC != gBAC")
	}
}

func TestKeyExchange(t *testing.T) {
	ikA := KeyExchangeKeyGen()
	ekA := KeyExchangeKeyGen()
	ikB := KeyExchangeKeyGen()
	ekB := KeyExchangeKeyGen()

	gAB := KeyExchange(true, ikA, PK(ikB), ekA, PK(ekB))
	gBA := KeyExchange(false, ikB, PK(ikA), ekB, PK(ekA))
	if gAB != gBA {
		t.Fatalf("gAB != gBA")
	}
}
