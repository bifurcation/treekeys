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
