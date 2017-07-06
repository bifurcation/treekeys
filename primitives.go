package treekeys

import (
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/curve25519"
)

func pow2(n int) int {
	m := 1
	for m < n {
		m <<= 1
	}
	return m >> 1
}

// XXX: This could just be the identity function, but let's add some hashing
// just to keep things interesting
func ι(element GroupElement) (priv PrivateKey) {
	h := sha256.New()
	h.Write(element[:])
	copy(priv[:], h.Sum(nil))
	return
}

func PK(priv PrivateKey) (pub GroupElement) {
	curve25519.ScalarBaseMult((*[32]byte)(&pub), (*[32]byte)(&priv))
	return
}

func Exp(pub GroupElement, priv PrivateKey) (out GroupElement) {
	curve25519.ScalarMult((*[32]byte)(&out), (*[32]byte)(&priv), (*[32]byte)(&pub))
	return
}

func DHKeyGen() (priv PrivateKey) {
	rand.Read(priv[:])
	return
}

func KeyExchangeKeyGen() PrivateKey {
	return DHKeyGen()
}

// XXX: Assuming something 3DH-like
func KeyExchange(originator bool, ikA PrivateKey, IKB GroupElement, ekA PrivateKey, EKB GroupElement) (priv PrivateKey) {
	iAB := Exp(EKB, ikA)
	iBA := Exp(IKB, ekA)
	eAB := Exp(EKB, ekA)

	if !originator {
		iAB, iBA = iBA, iAB
	}

	// XXX: Should use a proper KDF
	h := sha256.New()
	h.Write(iAB[:])
	h.Write(iBA[:])
	h.Write(eAB[:])
	copy(priv[:], h.Sum(nil))
	return
}
