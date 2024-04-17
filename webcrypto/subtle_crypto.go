package webcrypto

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash"

	"github.com/dop251/goja"
	"go.k6.io/k6/js/modules"
	"go.k6.io/k6/js/promises"
)

// FIXME: SubtleCrypto is described as an "interface", should it be a nested module
// with top-level functions instead then? (as opposed to a struct as it is now)

// FIXME: Make sure we cover the complete range of errors, and that their value makes sense

// SubtleCrypto represents the SubtleCrypto interface of the Web Crypto API.
type SubtleCrypto struct {
	vu modules.VU
}

// Encrypt encrypts data.
//
// It takes as its arguments a key to encrypt with, some algorithm-specific
// parameters, and the data to encrypt (also known as "plaintext").
//
// It returns a Promise which will be fulfilled with the encrypted data (also known as "ciphertext").
//
// The `algorithm` parameter should be one of:
//   - an `SubtleCrypto.RSAOaepParams` object
//   - an `SubtleCrypto.AESCtrParams` object
//   - an `SubtleCrypto.AESCbcParams` object
//   - an`SubtleCrypto.AESGcmParams` object
//
// The `key` parameter should be a `CryptoKey` to be used for encryption.
//
// The `data` parameter should contain the data to be encryption.
func (sc *SubtleCrypto) Encrypt( //nolint:dupl // we have two similar methods
	algorithm, key, data goja.Value,
) *goja.Promise {
	rt := sc.vu.Runtime()

	var (
		plaintext []byte
		ck        CryptoKey
		encrypter EncryptDecrypter
	)

	err := func() error {
		var err error

		plaintext, err = exportArrayBuffer(rt, data)
		if err != nil {
			return err
		}

		normalized, err := normalizeAlgorithm(rt, algorithm, OperationIdentifierEncrypt)
		if err != nil {
			return err
		}

		if err = rt.ExportTo(key, &ck); err != nil {
			return NewError(InvalidAccessError, "encrypt's key argument does hold not a valid CryptoKey object")
		}

		keyAlgorithmNameValue, err := traverseObject(rt, key.ToObject(rt), "algorithm", "name")
		if err != nil {
			return err
		}

		if normalized.Name != keyAlgorithmNameValue.String() {
			return NewError(InvalidAccessError, "encrypt's algorithm name does not match key algorithm name")
		}

		encrypter, err = newEncryptDecrypter(rt, normalized, algorithm)
		if err != nil {
			return err
		}

		if !ck.ContainsUsage(EncryptCryptoKeyUsage) {
			return NewError(InvalidAccessError, "encrypt's key does not contain the 'encrypt' usage")
		}

		return nil
	}()

	promise, resolve, reject := rt.NewPromise()
	if err != nil {
		reject(err)
		return promise
	}

	callback := sc.vu.RegisterCallback()
	go func() {
		result, err := encrypter.Encrypt(plaintext, ck)

		callback(func() error {
			if err != nil {
				reject(err)
				return nil //nolint:nilerr // we return nil to indicate that the error was handled
			}

			resolve(rt.NewArrayBuffer(result))
			return nil
		})
	}()

	return promise
}

// Decrypt decrypts some encrypted data.
//
// It takes as arguments a key to decrypt with, some optional extra parameters, and
// the data to decrypt (also known as "ciphertext").
//
// It returns a Promise which will be fulfilled with the decrypted data (also known
// as "plaintext").
//
// Note that if the provided `algorithm` is RSA-OAEP, the `key` parameter should hold
// the `PrivateKey` property of the `CryptoKeyPair`.
//
// The `algorithm` parameter should be one of:
//   - an `SubtleCrypto.RSAOaepParams` object
//   - an `SubtleCrypto.AESCtrParams` object
//   - an `SubtleCrypto.AESCbcParams` object
//   - an `SubtleCrypto.AESGcmParams` object
//
// The `key` parameter should be a `CryptoKey` to be used for decryption.
//
// The `data` parameter should contain the data to be decrypted.
func (sc *SubtleCrypto) Decrypt( //nolint:dupl // we have two similar methods
	algorithm, key, data goja.Value,
) *goja.Promise {
	rt := sc.vu.Runtime()

	var (
		ciphertext []byte
		ck         CryptoKey
		decrypter  EncryptDecrypter
	)

	err := func() error {
		var err error
		ciphertext, err = exportArrayBuffer(rt, data)
		if err != nil {
			return err
		}

		normalized, err := normalizeAlgorithm(rt, algorithm, OperationIdentifierDecrypt)
		if err != nil {
			return err
		}

		if err = rt.ExportTo(key, &ck); err != nil {
			return NewError(InvalidAccessError, "decrypt's key argument does hold not a valid CryptoKey object")
		}

		keyAlgorithmNameValue, err := traverseObject(rt, key.ToObject(rt), "algorithm", "name")
		if err != nil {
			return err
		}

		if normalized.Name != keyAlgorithmNameValue.String() {
			return NewError(InvalidAccessError, "decrypt's algorithm name does not match key algorithm name")
		}

		decrypter, err = newEncryptDecrypter(rt, normalized, algorithm)
		if err != nil {
			return err
		}

		if !ck.ContainsUsage(DecryptCryptoKeyUsage) {
			return NewError(InvalidAccessError, "decrypt's key does not contain the 'decrypt' usage")
		}

		return nil
	}()

	promise, resolve, reject := rt.NewPromise()
	if err != nil {
		reject(err)
		return promise
	}

	callback := sc.vu.RegisterCallback()
	go func() {
		result, err := decrypter.Decrypt(ciphertext, ck)

		callback(func() error {
			if err != nil {
				reject(err)
				return nil //nolint:nilerr // we return nil to indicate that the error was handled
			}

			resolve(rt.NewArrayBuffer(result))
			return nil
		})
	}()

	return promise
}

// Sign generates a digital signature.
//
// It takes as its arguments a key to sign with, some algorithm-specific parameters, and the data to sign.
// It returns a Promise which will be fulfilled with the signature.
//
// Note that if the `algorithm` parameter identifies a public-key cryptosystem, the `key` parameter
// should be a private key.
//
// You can use the corresponding `SubtleCrypto.Verify` method to verify the signature.
//
// The `algorithm` parameter should be one of:
//   - the string "RSASSA-PKCS1-v1_5" or an object of the form `{ "name": "RSASSA-PKCS1-v1_5" }`
//   - an `SubtleCrypto.RSAPssParams` object
//   - an `SubtleCrypto.EcdsaParams` object
//   - the string "HMAC" or an object of the form `{ "name": "HMAC" }`
//
// The `key` parameter should be a `CryptoKey` to be used for signing. Note that if
// `algorithm` identifies a public-key cryptosystem, this is the private key.
//
// The `data` parameter should contain the data to be signed.
func (sc *SubtleCrypto) Sign(algorithm, key, data goja.Value) *goja.Promise {
	rt := sc.vu.Runtime()

	var (
		dataToSign []byte
		ck         CryptoKey
		signer     SignerVerifier
	)

	err := func() error {
		var err error
		// 2.
		// We obtain a copy of the key data, because we might need to modify it.
		dataToSign, err = exportArrayBuffer(rt, data)
		if err != nil {
			return err
		}

		// 3.
		normalized, err := normalizeAlgorithm(rt, algorithm, OperationIdentifierSign)
		if err != nil {
			return err
		}

		signer, err = newSignerVerifier(rt, normalized, algorithm)
		if err != nil {
			return err
		}

		if err = rt.ExportTo(key, &ck); err != nil {
			return NewError(InvalidAccessError, "key argument does hold not a valid CryptoKey object")
		}

		keyAlgorithmNameValue, err := traverseObject(rt, key.ToObject(rt), "algorithm", "name")
		if err != nil {
			return err
		}

		// 8.
		if normalized.Name != keyAlgorithmNameValue.String() {
			return NewError(InvalidAccessError, "algorithm name does not match key algorithm name")
		}

		// 9.
		if !ck.ContainsUsage(SignCryptoKeyUsage) {
			return NewError(InvalidAccessError, "key does not contain the 'sign' usage")
		}

		return nil
	}()

	promise, resolve, reject := rt.NewPromise()
	if err != nil {
		reject(err)
		return promise
	}

	callback := sc.vu.RegisterCallback()
	go func() {
		signature, err := signer.Sign(ck, dataToSign)

		callback(func() error {
			if err != nil {
				reject(err)
				return nil //nolint:nilerr // we return nil to indicate that the error was handled
			}

			resolve(rt.NewArrayBuffer(signature))
			return nil
		})
	}()

	return promise
}

// Verify verifies a digital signature.
//
// It takes as its arguments a key to verify the signature with, some
// algorithm-specific parameters, the signature, and the original signed data.
//
// It returns a Promise which will be fulfilled with a boolean value indicating
// whether the signature is valid.
//
// Note that the `key` parameter should hold the secret key for a symmetric algorithm
// and the public key for a public-key system.
//
// The `algorithm` parameter should be one of:
//   - the string "RSASSA-PKCS1-v1_5" or an object of the form `{ "name": "RSASSA-PKCS1-v1_5" }`
//   - an `SubtleCrypto.RSAPssParams` object
//   - an `SubtleCrypto.EcdsaParams` object
//   - the string "HMAC" or an object of the form `{ "name": "HMAC" }`
//
// The `key` parameter should be a `CryptoKey` to be used for verification. Note that it
// is the secret key for a symmetric algorithm and the public key for a public-key system.
//
// The `signature` parameter should contain the signature to be verified.
//
// The `data` parameter should contain the original signed data.
func (sc *SubtleCrypto) Verify(algorithm, key, signature, data goja.Value) *goja.Promise {
	rt := sc.vu.Runtime()

	var (
		signatureData, signedData []byte
		verifier                  SignerVerifier
		ck                        CryptoKey
	)

	err := func() error {
		var err error

		signatureData, err = exportArrayBuffer(sc.vu.Runtime(), signature)
		if err != nil {
			return err
		}

		signedData, err = exportArrayBuffer(sc.vu.Runtime(), data)
		if err != nil {
			return err
		}

		normalizedAlgorithm, err := normalizeAlgorithm(rt, algorithm, OperationIdentifierVerify)
		if err != nil {
			return err
		}

		verifier, err = newSignerVerifier(rt, normalizedAlgorithm, algorithm)
		if err != nil {
			return err
		}

		if err = rt.ExportTo(key, &ck); err != nil {
			return NewError(InvalidAccessError, "key argument does hold not a valid CryptoKey object")
		}

		keyAlgorithmNameValue, err := traverseObject(rt, key, "algorithm", "name")
		if err != nil {
			return err
		}

		if normalizedAlgorithm.Name != keyAlgorithmNameValue.String() {
			return NewError(InvalidAccessError, "algorithm name does not match key algorithm name")
		}

		if !ck.ContainsUsage(VerifyCryptoKeyUsage) {
			return NewError(InvalidAccessError, "key does not contain the 'sign' usage")
		}

		return nil
	}()

	promise, resolve, reject := rt.NewPromise()
	if err != nil {
		reject(err)
		return promise
	}

	callback := sc.vu.RegisterCallback()
	go func() {
		verified, err := verifier.Verify(ck, signatureData, signedData)

		callback(func() error {
			if err != nil {
				reject(err)
				return nil //nolint:nilerr // we return nil to indicate that the error was handled
			}

			resolve(verified)
			return nil
		})
	}()

	return promise
}

// Digest generates a digest of the given data.
//
// A digest is a short fixed-length value derived from some
// variable-length input. Cryptographic digests should exhibit
// collision-resistance, meaning that it's hard to come up with
// two different inputs that have the same digest value.
//
// It takes as its arguments an identifier for the digest algorithm
// to use and the data to digest.
// It returns a Promise which will be fulfilled with the digest.
//
// Supported digest algorithms:
//   - SHA-1 (not to be used in cryptographic applications)
//   - SHA-256
//   - SHA-384
//   - SHA-512
//
// The `data` parameter should contain the data to be digested.
func (sc *SubtleCrypto) Digest(algorithm goja.Value, data goja.Value) *goja.Promise {
	rt := sc.vu.Runtime()

	var (
		hashFn func() hash.Hash
		bytes  []byte
	)

	err := func() error {
		var err error

		// Validate that the value we received is either an ArrayBuffer, TypedArray, or DataView
		// This uses the technique described in https://github.com/dop251/goja/issues/379#issuecomment-1164441879
		if !IsInstanceOf(sc.vu.Runtime(), data, ArrayBufferConstructor, DataViewConstructor) &&
			!IsTypedArray(sc.vu.Runtime(), data) {
			return errors.New("data must be an ArrayBuffer, TypedArray, or DataView")
		}

		bytes, err = exportArrayBuffer(rt, data)
		if err != nil {
			return err
		}

		normalized, err := normalizeAlgorithm(rt, algorithm, OperationIdentifierDigest)
		if err != nil {
			return err
		}

		var ok bool
		hashFn, ok = getHashFn(normalized.Name)
		if !ok {
			return NewError(NotSupportedError, "unsupported algorithm: "+normalized.Name)
		}

		return nil
	}()

	promise, resolve, reject := rt.NewPromise()
	if err != nil {
		reject(err)
		return promise
	}

	callback := sc.vu.RegisterCallback()
	go func() {
		hash := hashFn()
		hash.Write(bytes)
		digest := hash.Sum(nil)

		callback(func() error {
			if err != nil {
				reject(err)
				return nil //nolint:nilerr // we return nil to indicate that the error was handled
			}

			resolve(rt.NewArrayBuffer(digest))
			return nil
		})
	}()

	return promise
}

// GenerateKey generate a new key (for symmetric algorithms) or key pair (for public-key algorithms).
//
// The generated key will match the algorithm, usages, and extractability given
// as parameters.
//
// It returns a Promise that fulfills with a `SubtleCrypto.CryptoKey` (for symmetric algorithms)
// or a `SubtleCrypto.CryptoKeyPair` (for public-key algorithms).
//
// The `algorithm` parameter should be one of:
//   - for RSASSA-PKCS1-v1_5, RSA-PSS, or RSA-OAEP: pass an `SubtleCrypto.RSAHashedKeyGenParams` object
//   - for ECDSA or ECDH: pass an `SubtleCrypto.ECKeyGenParams` object
//   - an `SubtleCrypto.HMACKeyGenParams` object
//   - for AES-CTR, AES-CBC, AES-GCM, AES-KW: pass an `SubtleCrypto.AESKeyGenParams`
//
// The `extractable` parameter indicates whether it will be possible to export the key
// using `SubtleCrypto.ExportKey` or `SubtleCrypto.WrapKey`.
//
// The `keyUsages` parameter is an array of strings indicating what the key can be used for.
func (sc *SubtleCrypto) GenerateKey(algorithm goja.Value, extractable bool, keyUsages []CryptoKeyUsage) *goja.Promise {
	promise, resolve, reject := promises.New(sc.vu)

	normalized, err := normalizeAlgorithm(sc.vu.Runtime(), algorithm, OperationIdentifierGenerateKey)
	if err != nil {
		reject(err)
		return promise
	}

	keyGenerator, err := newKeyGenerator(sc.vu.Runtime(), normalized, algorithm)
	if err != nil {
		reject(err)
		return promise
	}

	go func() {
		// 7.
		result, err := keyGenerator.GenerateKey(extractable, keyUsages)
		if err != nil {
			reject(err)
			return
		}

		if !result.IsKeyPair() {
			cryptoKey, err := result.ResolveCryptoKey()
			if err != nil {
				reject(NewError(OperationError, "usages cannot not be empty for a secret or private CryptoKey"))
				return
			}

			// 8.
			isSecretKey := cryptoKey.Type == SecretCryptoKeyType
			isPrivateKey := cryptoKey.Type == PrivateCryptoKeyType
			isUsagesEmpty := len(cryptoKey.Usages) == 0
			if (isSecretKey || isPrivateKey) && isUsagesEmpty {
				reject(NewError(SyntaxError, "usages cannot not be empty for a secret or private CryptoKey"))
				return
			}
		}

		resolve(result)
	}()

	return promise
}

// DeriveKey can be used to derive a secret key from a master key.
//
// It takes as arguments some initial key material, the derivation
// algorithm to use, and the desired properties for the key to derive.
// It returns a Promise which will be fulfilled with a CryptoKey object
// representing the new key.
//
// Note that if the `algorithm` parameter is ECDH, the `baseKey` parameter
// should be a private key. Otherwise, it should be the initial key material for
// the derivation function: for example, for PBKDF2 it might be a password, imported
// as a CryptoKey using `SubtleCrypto.ImportKey`.
//
// The `algorithm` parameter should be one of:
//   - an `SubtleCrypto.ECDHKeyDeriveParams` object
//   - an `SubtleCrypto.HKDFParams` object
//   - an `SubtleCrypto.Pbkdf2Params` object
//
// The `baseKey` parameter should be a CryptoKey object representing the input
// to the derivation algorithm. If `algorithm` is ECDH, then this will be the
// ECDH private key. Otherwise it will be the initial key material for the derivation
// function: for example, for PBKDF2 it might be a password, imported as a `SubtleCrypto.CryptoKey`
// using `SubtleCrypto.ImportKey`.
//
// The `derivedKeyAlgorithm` parameter should be one of:
//   - an `SubtleCrypto.HMACKeyGenParams` object
//   - For AES-CTR, AES-CBC, AES-GCM, AES-KW: pass an `SubtleCrypto.AESKeyGenParams`
//
// The `extractable` parameter indicates whether it will be possible to export the key
// using `SubtleCrypto.ExportKey` or `SubtleCrypto.WrapKey`.
//
// The `keyUsages` parameter is an array of strings indicating what the key can be used for.
//
//nolint:revive // remove the nolint directive when the method is implemented
func (sc *SubtleCrypto) DeriveKey(
	algorithm goja.Value,
	baseKey goja.Value,
	derivedKeyAlgorithm goja.Value,
	extractable bool,
	keyUsages []CryptoKeyUsage,
) *goja.Promise {
	// TODO: implementation
	return nil
}

// DeriveBits derives an array of bits from a base key.
//
// It takes as its arguments the base key, the derivation algorithm to use, and the length of the bit string to derive.
// It returns a Promise which will be fulfilled with an ArrayBuffer containing the derived bits.
//
// This method is very similar to `SubtleCrypto.DeriveKey`, except that `SubtleCrypto.DeriveKey` returns
// a `CryptoKey` object rather than an ArrayBuffer. Essentially `SubtleCrypto.DeriveKey` is composed
// of `SubtleCrypto.DeriveBits` followed by `SubtleCrypto.ImportKey`.
//
// This function supports the same derivation algorithms as deriveKey(): ECDH, HKDF, and PBKDF2
//
// Note that if the `algorithm` parameter is ECDH, the `baseKey` parameter should be the ECDH private key.
// Otherwise it should be the initial key material for the derivation function: for example, for PBKDF2 it might
// be a password, imported as a `CryptoKey` using `SubtleCrypto.ImportKey`.
//
// The `algorithm` parameter should be one of:
//   - an `SubtleCrypto.ECDHKeyDeriveParams` object
//   - an `SubtleCrypto.HKDFParams` object
//   - an `SubtleCrypto.PBKDF2Params` object
//
// The `baseKey` parameter should be a `CryptoKey` object representing the input to the derivation algorithm.
// If `algorithm` is ECDH, then this will be the ECDH private key. Otherwise it will be the initial key material
// for the derivation function: for example, for PBKDF2 it might be a password, imported as a `CryptoKey`
// using `SubtleCrypto.ImportKey`.
//
// The `length` parameter is the number of bits to derive. The number should be a multiple of 8.
func (sc *SubtleCrypto) DeriveBits(algorithm goja.Value, baseKey goja.Value, length int) *goja.Promise {
	rt := sc.vu.Runtime()

	var publicKey, privateKey CryptoKey
	var algName string

	err := func() error {
		if err := rt.ExportTo(baseKey, &privateKey); err != nil {
			return NewError(InvalidAccessError, "provided baseKey is not a valid CryptoKey")
		}

		if privateKey.Type != PrivateCryptoKeyType {
			return NewError(InvalidAccessError, fmt.Sprintf("provided baseKey is not a private key: %v", privateKey))
		}

		alg := algorithm.ToObject(rt)

		pcValue := alg.Get("public")
		if err := rt.ExportTo(pcValue, &publicKey); err != nil {
			return NewError(InvalidAccessError, "algorithm's public is not a valid CryptoKey")
		}

		algName = alg.Get("name").String()

		if publicKey.Type != PublicCryptoKeyType {
			return NewError(InvalidAccessError, "algorithm's public key is not a public key")
		}

		return nil
	}()

	promise, resolve, reject := rt.NewPromise()
	if err != nil {
		reject(err)
		return promise
	}

	callback := sc.vu.RegisterCallback()
	go func() {
		result, err := func() ([]byte, error) {
			deriver, err := newBitsDeriver(algName)
			if err != nil {
				return nil, err
			}

			b, err := deriver(privateKey, publicKey)
			if err != nil {
				return nil, NewError(OperationError, err.Error())
			}

			if len(b) < length/8 {
				return nil, NewError(OperationError, "length is too large")
			}

			return b[:length/8], nil
		}()

		callback(func() error {
			if err != nil {
				reject(err)
				return nil //nolint:nilerr // we return nil to indicate that the error was handled
			}

			resolve(rt.NewArrayBuffer(result))
			return nil
		})
	}()

	return promise
}

// ImportKey imports a key: that is, it takes as input a key in an external, portable
// format and gives you a CryptoKey object that you can use in the Web Crypto API.
//
// It returns a Promise that fulfills with the imported key as a CryptoKey object.
//
// The `format` parameter identifies the format of the key data.
//
// The `keyData` parameter is the key data, in the format specified by the `format` parameter.
//
// The `algorithm` parameter should be one of:
//   - for RSASSA-PKCS1-v1_5, RSA-PSS or RSA-OAEP: pass an `SubtleCrypto.RSAHashedImportParams` object
//   - for ECDSA or ECDH: pass an `SubtleCrypto.EcKeyImportParams` object
//   - an `SubtleCrypto.HMACImportParams` object
//   - for AES-CTR, AES-CBC, AES-GCM or AES-KW pass the string identifying
//     the algorithm or an object of the form `{ name: ALGORITHM }`, where
//     `ALGORITHM` is the name of the algorithm.
//   - for PBKDF2: pass the string "PBKDF2"
//   - for HKDF: pass the string "HKDF"
func (sc *SubtleCrypto) ImportKey(
	format KeyFormat,
	keyData goja.Value,
	algorithm goja.Value,
	extractable bool,
	keyUsages []CryptoKeyUsage,
) *goja.Promise {
	rt := sc.vu.Runtime()
	promise, resolve, reject := promises.New(sc.vu)

	var keyBytes []byte

	// 2.
	switch format {
	case Pkcs8KeyFormat, RawKeyFormat, SpkiKeyFormat:
		ab, err := exportArrayBuffer(rt, keyData)
		if err != nil {
			reject(err)
			return promise
		}

		keyBytes = make([]byte, len(ab))
		copy(keyBytes, ab)
	case JwkKeyFormat:
		var err error
		keyBytes, err = json.Marshal(keyData.Export())
		if err != nil {
			reject(NewError(ImplementationError, "wrong keyData format for JWK format: "+err.Error()))
			return promise
		}
	default:
		reject(NewError(ImplementationError, "unsupported format "+format))
		return promise
	}

	// 3.
	normalized, err := normalizeAlgorithm(rt, algorithm, OperationIdentifierImportKey)
	if err != nil {
		reject(err)
		return promise
	}

	ki, err := newKeyImporter(rt, normalized, algorithm)
	if err != nil {
		reject(err)
		return promise
	}

	// 5.
	go func() {
		// 8.
		result, err := ki.ImportKey(format, keyBytes, keyUsages)
		if err != nil {
			reject(err)
			return
		}

		// 9.
		isSecretKey := result.Type == SecretCryptoKeyType
		isPrivateKey := result.Type == PrivateCryptoKeyType
		isUsagesEmpty := len(keyUsages) == 0
		if (isSecretKey || isPrivateKey) && isUsagesEmpty {
			reject(NewError(SyntaxError, "usages cannot not be empty for a secret or private CryptoKey"))
			return
		}

		// 10.
		result.Extractable = extractable

		// 11.
		result.Usages = keyUsages

		// 12.
		resolve(result)
	}()

	return promise
}

// ExportKey exports a key: that is, it takes as input a CryptoKey object and gives
// you the key in an external, portable format.
//
// To export a key, the key must have CryptoKey.extractable set to true.
//
// Keys are not exported in an encrypted format: to encrypt keys when exporting
// them use the SubtleCrypto.wrapKey() API instead.
//
// It returns A Promise:
//   - If format was jwk, then the promise fulfills with a JSON object containing the key.
//   - Otherwise the promise fulfills with an ArrayBuffer containing the key.
//
// The `format` parameter identifies the format of the key data.
// The `key` parameter is the key to export, as a CryptoKey object.
func (sc *SubtleCrypto) ExportKey(format KeyFormat, key goja.Value) *goja.Promise {
	rt := sc.vu.Runtime()
	promise, resolve, reject := promises.New(sc.vu)

	var algorithm Algorithm
	algValue := key.ToObject(rt).Get("algorithm")
	if err := rt.ExportTo(algValue, &algorithm); err != nil {
		reject(NewError(SyntaxError, "key is not a valid CryptoKey"))
		return promise
	}

	ck, ok := key.Export().(*CryptoKey)
	if !ok {
		reject(NewError(ImplementationError, "unable to extract CryptoKey"))
		return promise
	}

	inputAlgorithm := key.ToObject(rt).Get("algorithm").ToObject(rt)

	keyAlgorithmName := inputAlgorithm.Get("name").String()
	if algorithm.Name != keyAlgorithmName {
		reject(NewError(InvalidAccessError, "algorithm name does not match key algorithm name"))
		return promise
	}

	go func() {
		// 5.
		if !isRegisteredAlgorithm(algorithm.Name, OperationIdentifierExportKey) {
			reject(NewError(NotSupportedError, "unsupported algorithm "+algorithm.Name))
			return
		}

		// 6.
		if !ck.Extractable {
			reject(NewError(InvalidAccessError, "the key is not extractable"))
			return
		}

		var result interface{}
		var err error

		switch keyAlgorithmName {
		case AESCbc, AESCtr, AESGcm:
			result, err = exportAESKey(ck, format)
			if err != nil {
				reject(err)
				return
			}
		case HMAC:
			result, err = exportHMACKey(ck, format)
			if err != nil {
				reject(err)
				return
			}
		case ECDH, ECDSA:
			result, err = exportECKey(keyAlgorithmName, ck, format)
			if err != nil {
				reject(err)
				return
			}
		default:
			reject(NewError(NotSupportedError, "unsupported algorithm "+keyAlgorithmName))
			return
		}

		if !isBinaryExportedFormat(format) {
			resolve(result)
			return
		}

		b, ok := result.([]byte)
		if !ok {
			reject(NewError(ImplementationError, "for "+format+" []byte expected as result"))
			return
		}

		resolve(rt.NewArrayBuffer(b))
	}()

	return promise
}

func isBinaryExportedFormat(format KeyFormat) bool {
	return format == RawKeyFormat || format == Pkcs8KeyFormat || format == SpkiKeyFormat
}

// WrapKey  "wraps" a key.
//
// This means that it exports the key in an external, portable format, then encrypts the exported key.
// Wrapping a key helps protect it in untrusted environments, such as inside an otherwise unprotected data
// store or in transmission over an unprotected network.
//
// As with `SubtleCrypto.ExportKey`, you specify an export format for the key.
// To export a key, it must have `CryptoKey.Extractable` set to true.
//
// But because `SubtleCrypto.WrapKey“ also encrypts the key to be imported, you
// also need to pass in the key that must be used to encrypt it. This is sometimes called the "wrapping key".
//
// The inverse of `SubtleCrypto.WrapKey` is `SubtleCrypto.UnwrapKey`: while `SubtleCrypto.WrapKey“ is composed
// of export + encrypt, unwrapKey is composed of import + decrypt.
//
// It returns a Promise that fulfills with an ArrayBuffer containing the encrypted exported key.
//
// The `format` parameter identifies the format of the key data.
// The `key` parameter is the key to export, as a CryptoKey object.
// The `wrappingKey` parameter is the key to use to encrypt the exported key. The key **must** have
// the `wrapKey` usage flag set.
// The `wrapAlgorithm` parameter identifies the algorithm to use to encrypt the exported key, and should be one of:
//   - an `SubtleCrypto.RSAOaepParams` object
//   - an `SubtleCrypto.AesCtrParams` object
//   - an `SubtleCrypto.AesCbcParams` object
//   - an `SubtleCrypto.AesGcmParams` object
//   - for the AES-KW algorithm, pass the string "AES-KW", or an object of the form `{ name: "AES-KW" }`
//
//nolint:revive // remove the nolint directive when the method is implemented
func (sc *SubtleCrypto) WrapKey(
	format KeyFormat,
	key goja.Value,
	wrappingKey goja.Value,
	wrapAlgorithm goja.Value,
) *goja.Promise {
	// TODO: implementation
	return nil
}

// UnwrapKey "unwraps" a key.
//
// This means that it takes as its input a key that has been exported and then
// encrypted (also called "wrapped"). It decrypts the key and then imports it, returning
// a `CryptoKey` object that can be used in the Web Crypto API.
//
// As with `SubtleCrypto.ImportKey`, you specify the key's import format and other attributes
// of the key to import details such as whether it is extractable, and which operations it can be used for.
//
// But because `SubtleCrypto.UnwrapKey` also decrypts the key to be imported, you also need to pass
// in the key that must be used to decrypt it. This is sometimes called the "unwrapping key".
//
// The inverse of `SubtleCrypto.UnwrapKey` is `SubtleCrypto.WrapKey`: while `SubtleCrypto.UnwrapKey` is composed
// of decrypt + import, `Subtle.WrapKey` is composed of encrypt + export.
//
// It returns a Promise that fulfills with the unwrapped key as a CryptoKey object.
//
// The `format` parameter identifies the format of the key data.
//
// The `wrappedKey` parameter is the key to unwrap.
//
// The `unwrappingKey` parameter is the key to use to decrypt the wrapped key. The key **must** have
//
// the `unwrapKey` usage flag set.
//
// The `unwrapAlgorithm` parameter identifies the algorithm to use to decrypt the wrapped key, and should be one of:
//   - an `SubtleCrypto.RSAOaepParams` object
//   - an `SubtleCrypto.AesCtrParams` object
//   - an `SubtleCrypto.AesCbcParams` object
//   - an `SubtleCrypto.AesGcmParams` object
//   - for the AES-KW algorithm, pass the string "AES-KW", or an object of the form `{ name: "AES-KW" }`
//
// The `unwrappedKeyAlgorithm` parameter identifies the algorithm to use to import the unwrapped
// key, and should be one of:
//   - for RSASSA-PKCS1-v1_5, RSA-PSS or RSA-OAEP: pass an `SubtleCrypto.RSAHashedImportParams` object
//   - for ECDSA or ECDH: pass an `SubtleCrypto.EcKeyImportParams` object
//   - for HMAC: pass an `SubtleCrypto.HMACImportParams` object
//   - for AES-CTR, AES-CBC, AES-GCM or AES-KW pass the string identifying the algorithm or an object of the form
//     `{ name: ALGORITHM }`, where `ALGORITHM` is the name of the algorithm.
//
// The `extractable` parameter identifies whether the key is extractable.
//
// The `keyUsages` parameter identifies the operations that the key can be used for.
//
//nolint:revive // remove the nolint directive when the method is implemented
func (sc *SubtleCrypto) UnwrapKey(
	format KeyFormat,
	wrappedKey []byte,
	unwrappingKey goja.Value,
	unwrapAlgo goja.Value,
	unwrappedKeyAlgo goja.Value,
	extractable bool,
	keyUsages []CryptoKeyUsage,
) *goja.Promise {
	// TODO: implementation
	return nil
}
