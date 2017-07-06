package treekeys

import (
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/curve25519"
)

func ceillog2(n int) int {
	l := 0
	for n > (1 << uint(l)) {
		l += 1
	}
	return l
}

func pow2(n int) int {
	m := 1
	for m < n {
		m <<= 1
	}
	return m >> 1
}

// TODO: Use a real KDF and/or structure inputs better
func KDF(vals ...[]byte) (out PrivateKey) {
	h := sha256.New()
	for _, val := range vals {
		h.Write(val[:])
	}
	h.Sum(out[:])
	return
}

// XXX: This could just be the identity function, but let's add some hashing
// just to keep things interesting
func ι(element GroupElement) PrivateKey {
	return KDF(element[:])
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
func KeyExchange(originator bool, ikA PrivateKey, IKB GroupElement, ekA PrivateKey, EKB GroupElement) PrivateKey {
	iAB := Exp(EKB, ikA)
	iBA := Exp(IKB, ekA)
	eAB := Exp(EKB, ekA)

	if !originator {
		iAB, iBA = iBA, iAB
	}

	return KDF(iAB[:], iBA[:], eAB[:])
}
