package webcrypto

import (
	"reflect"
	"strings"

	"github.com/dop251/goja"
)

// Algorithm represents
type Algorithm struct {
	Name AlgorithmIdentifier `json:"name"`
}

// AlgorithmIdentifier represents the name of an algorithm.
// As defined by the [specification]
//
// Note that it is defined as an alias of string, instead of a dedicated type,
// to ensure it is handled as a string by goja.
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#algorithm-dictionary
type AlgorithmIdentifier = string

const (
	// RSASsaPkcs1v15 represents the RSA-SHA1 algorithm.
	RSASsaPkcs1v15 = "RSASSA-PKCS1-v1_5"

	// RSAPss represents the RSA-PSS algorithm.
	RSAPss = "RSA-PSS"

	// RSAOaep represents the RSA-OAEP algorithm.
	RSAOaep = "RSA-OAEP"

	// HMAC represents the HMAC algorithm.
	HMAC = "HMAC"

	// AESCtr represents the AES-CTR algorithm.
	AESCtr = "AES-CTR"

	// AESCbc represents the AES-CBC algorithm.
	AESCbc = "AES-CBC"

	// AESGcm represents the AES-GCM algorithm.
	AESGcm = "AES-GCM"

	// AESKw represents the AES-KW algorithm.
	AESKw = "AES-KW"

	// ECDSA represents the ECDSA algorithm.
	ECDSA = "ECDSA"

	// ECDH represents the ECDH algorithm.
	ECDH = "ECDH"
)

// HashAlgorithmIdentifier represents the name of a hash algorithm.
//
// Note that it is defined as an alias of string, instead of a dedicated type,
// to ensure it is handled as a string under the hood by goja.
type HashAlgorithmIdentifier = AlgorithmIdentifier

const (
	// Sha1 represents the SHA-1 algorithm.
	Sha1 HashAlgorithmIdentifier = "SHA-1"

	// Sha256 represents the SHA-256 algorithm.
	Sha256 = "SHA-256"

	// Sha384 represents the SHA-384 algorithm.
	Sha384 = "SHA-384"

	// Sha512 represents the SHA-512 algorithm.
	Sha512 = "SHA-512"
)

// OperationIdentifier represents the name of an operation.
//
// Note that it is defined as an alias of string, instead of a dedicated type,
// to ensure it is handled as a string by goja.
type OperationIdentifier = string

const (
	// OperationIdentifierSign represents the sign operation.
	OperationIdentifierSign OperationIdentifier = "sign"

	// OperationIdentifierVerify represents the verify operation.
	OperationIdentifierVerify OperationIdentifier = "verify"

	// OperationIdentifierEncrypt represents the encrypt operation.
	OperationIdentifierEncrypt OperationIdentifier = "encrypt"

	// OperationIdentifierDecrypt represents the decrypt operation.
	OperationIdentifierDecrypt OperationIdentifier = "decrypt"

	// OperationIdentifierDeriveBits represents the deriveBits operation.
	OperationIdentifierDeriveBits OperationIdentifier = "deriveBits"

	// OperationIdentifierDeriveKey represents the deriveKey operation.
	OperationIdentifierDeriveKey OperationIdentifier = "deriveKey"

	// OperationIdentifierWrapKey represents the wrapKey operation.
	OperationIdentifierWrapKey OperationIdentifier = "wrapKey"

	// OperationIdentifierUnwrapKey represents the unwrapKey operation.
	OperationIdentifierUnwrapKey OperationIdentifier = "unwrapKey"

	// OperationIdentifierImportKey represents the importKey operation.
	OperationIdentifierImportKey OperationIdentifier = "importKey"

	// OperationIdentifierExportKey represents the exportKey operation.
	OperationIdentifierExportKey OperationIdentifier = "exportKey"

	// OperationIdentifierGenerateKey represents the generateKey operation.
	OperationIdentifierGenerateKey OperationIdentifier = "generateKey"

	// OperationIdentifierDigest represents the digest operation.
	OperationIdentifierDigest OperationIdentifier = "digest"
)

// normalizeAlgorithm normalizes the given algorithm following the
// algorithm described in the WebCrypto [specification].
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#algorithm-normalization-normalize-an-algorithm
func normalizeAlgorithm(rt *goja.Runtime, v goja.Value, op AlgorithmIdentifier) (Algorithm, error) {
	var algorithm Algorithm

	// "if alg is an instance of a DOMString: return the result of the running the
	// normalize algorithm, with the `alg` set to a new Algorithm object whose name
	// attribute is set to alg, and with the op set to op."
	if v.ExportType().Kind() == reflect.String {
		algorithmString, ok := v.Export().(string)
		if !ok {
			return Algorithm{}, NewError(0, ImplementationError, "algorithm cannot be interpreted as a string")
		}

		algorithmObject := rt.NewObject()
		if err := algorithmObject.Set("name", algorithmString); err != nil {
			return Algorithm{}, NewError(0, ImplementationError, "unable to transform algorithm string into an object")
		}

		return normalizeAlgorithm(rt, algorithmObject, op)
	}

	if err := rt.ExportTo(v, &algorithm); err != nil {
		return Algorithm{}, NewError(0, SyntaxError, "algorithm cannot be interpreted as a string or an object")
	}

	// Algorithm identifers are always upper cased.
	// A registered algorithm provided in lower case format, should
	// be considered valid.
	algorithm.Name = strings.ToUpper(algorithm.Name)

	if !isRegisteredAlgorithm(algorithm.Name, op) {
		return Algorithm{}, NewError(0, NotSupportedError, "unsupported algorithm: "+algorithm.Name)
	}

	return algorithm, nil
}

// isRegisteredAlgorithm returns true if the given algorithm name is registered
// for the given operation. As per steps 1. and 5. of the WebCrypto specification's
// "[algorithm normalization]" algorithm.
//
// [algorithm normalization]: https://www.w3.org/TR/WebCryptoAPI/#algorithm-normalization-normalize-an-algorithm
func isRegisteredAlgorithm(algorithmName string, forOperation string) bool {
	isAesCbc := algorithmName == AESCbc
	isAesCtr := algorithmName == AESCtr
	isAesGcm := algorithmName == AESGcm
	isAesKw := algorithmName == AESKw

	switch forOperation {
	case OperationIdentifierDigest:
		isSha1 := algorithmName == Sha1
		isSha256 := algorithmName == Sha256
		isSha384 := algorithmName == Sha384
		isSha512 := algorithmName == Sha512
		return isSha1 || isSha256 || isSha384 || isSha512
	case OperationIdentifierGenerateKey:
		return isAesCbc || isAesCtr || isAesGcm || isAesKw
	case OperationIdentifierExportKey, OperationIdentifierImportKey:
		return isAesCbc || isAesCtr || isAesGcm
	case OperationIdentifierEncrypt:
		return isAesCbc || isAesCtr || isAesGcm
	default:
		return false
	}
}
