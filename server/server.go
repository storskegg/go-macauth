package server

import (
	"crypto/rand"
	"encoding"
	"errors"

	macauth "keybase/hmac-header"

	"github.com/eknkc/basex"
	"github.com/jzelinskie/whirlpool"
)

var (
	ErrNotPowerOfTwo = errors.New("expected power of two")
)

// powerOf2 tests whether the parameter `x` is a power of 2, and returns a boolean. O(1)
func powerOf2(x int) bool {
	return x&(x-1) == 0
}

func NewSecret(randLength int) (string, error) {
	if randLength < 1 {
		randLength = 1024
	}
	if ok := powerOf2(randLength); !ok {
		return "", ErrNotPowerOfTwo
	}

	idxHalf := randLength / 2

	b := make([]byte, randLength)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	w := whirlpool.New()
	w.Write(b[:idxHalf])
	h1 := w.Sum(nil)
	w.Reset()
	w.Write(b[idxHalf:])
	h2 := w.Sum(nil)
	w.Reset()

	e, err := basex.NewEncoding(macauth.EncodingDictionary)
	if err != nil {
		return "", err
	}
	s1 := e.Encode(h1)
	s2 := e.Encode(h2)

	secret := s1 + "::::" + s2
	return secret, nil
}

func E(enc encoding.TextMarshaler)
