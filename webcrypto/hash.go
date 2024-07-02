package webcrypto

import (
	"crypto"
	"hash"
)

// getHashFn returns the hash function associated with the given name.
//
// It returns a generator function, that can be used to create a new
// hash.Hash instance.
func getHashFn(name string) (func() hash.Hash, bool) {
	switch name {
	case SHA1:
		return crypto.SHA1.New, true
	case SHA256:
		return crypto.SHA256.New, true
	case SHA384:
		return crypto.SHA384.New, true
	case SHA512:
		return crypto.SHA512.New, true
	default:
		return nil, false
	}
}

// getCryptoHash returns the hash associated with the given name.
//
// crypto.Hash instance.
func getCryptoHash(name string) (crypto.Hash, bool) {
	switch name {
	case SHA1:
		return crypto.SHA1, true
	case SHA256:
		return crypto.SHA256, true
	case SHA384:
		return crypto.SHA384, true
	case SHA512:
		return crypto.SHA512, true
	default:
		// FIXME
		return 20, false
	}
}
// hasHash an internal interface that helps us to identify
// if a given object has a hash method.
type hasHash interface {
	hash() string
}
