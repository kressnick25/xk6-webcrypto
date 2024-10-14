package webcrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"

	"github.com/grafana/sobek"
)

// RsaKeyAlgorithm represents the [RSA key algorithm].
//
// [RSA key algorithm]: https://www.w3.org/TR/WebCryptoAPI/#RsaKeyAlgorithm-dictionary
type RsaKeyAlgorithm struct {
	KeyAlgorithm

	// ModulusLength contains the length, in bits, of the RSA modulus.
	ModulusLength uint32 `js:"modulusLength"`

	// PublicExponent contains the RSA public exponent value of the key to generate.
	PublicExponent []byte `js:"publicExponent"`
}

// RsaHashedKeyAlgorithm represents the [RSA algorithm for hashed keys].
//
// [RSA algorithm for hashed keys]: https://www.w3.org/TR/WebCryptoAPI/#RsaHashedKeyAlgorithm-dictionary
type RsaHashedKeyAlgorithm struct {
	RsaKeyAlgorithm

	// Hash contains the hash algorithm that is used with this key.
	Hash KeyAlgorithm `js:"hash"`
}

// RsaKeyGenParams represents the [RSA key generation parameters].
//
// [RSA key generation parameters]: https://www.w3.org/TR/WebCryptoAPI/#RsaKeyGenParams-dictionary
type RsaKeyGenParams struct {
	Algorithm

	// ModulusLength contains the length, in bits, of the RSA modulus.
	ModulusLength uint32 `js:"modulusLength"`

	// PublicExponent contains the RSA public exponent value of the key to generate.
	PublicExponent []byte `js:"publicExponent"`
}

// RsaHashedKeyGenParams represents the RSA algorithm for hashed keys [key generation parameters].
//
// [key generation parameters]: https://www.w3.org/TR/WebCryptoAPI/#RsaHashedKeyGenParams-dictionary
type RsaHashedKeyGenParams struct {
	RsaKeyGenParams

	// Hash contains the hash algorithm to use.
	Hash HashAlgorithmIdentifier `js:"hash"`
}

// NewRsaHashedKeyGenParams creates a new RsaHashedKeyGenParams instance from a sobek.Value.
func newRsaHashedKeyGenParams(rt *sobek.Runtime, normalized Algorithm, v sobek.Value) (*RsaHashedKeyGenParams, error) {
	if v == nil {
		return &RsaHashedKeyGenParams{}, NewError(SyntaxError, "algorithm is required")
	}

	var params RsaHashedKeyGenParams
	if err := rt.ExportTo(v, &params); err != nil {
		return &RsaHashedKeyGenParams{}, NewError(SyntaxError, "algorithm is invalid")
	}

	// Because the hash field can either be a string or an object, we need to
	// handle it specifically.
	if hash, ok := v.ToObject(rt).Get("hash").Export().(string); ok {
		params.Hash = hash
	} else {
		var hash Algorithm
		if err := rt.ExportTo(v.ToObject(rt).Get("hash"), &hash); err != nil {
			return &RsaHashedKeyGenParams{}, NewError(SyntaxError, "hash algorithm is invalid")
		}
		params.Hash = hash.Name
	}

	if err := params.validate(); err != nil {
		return &RsaHashedKeyGenParams{}, err
	}

	params.Algorithm = normalized

	return &params, nil
}

// Validate validates the RsaHashedKeyGenParams instance. It implements the
// Validator interface.
func (r RsaHashedKeyGenParams) validate() error {
	if r.Name == "" {
		return NewError(SyntaxError, "name is required")
	}

	if r.PublicExponent == nil {
		return NewError(OperationError, "publicExponent is required")
	}

	if len(r.PublicExponent) != 3 {
		return NewError(OperationError, "publicExponent must be 3 bytes")
	}

	if r.PublicExponent[0] != 0x01 || r.PublicExponent[1] != 0x00 || r.PublicExponent[2] != 0x01 {
		return NewError(OperationError, "publicExponent must be 0x010001")
	}

	if r.Hash == "" {
		return NewError(SyntaxError, "hash is required")
	}

	if !isHashAlgorithm(r.Hash) {
		return NewError(NotSupportedError, "unsupported hash algorithm")
	}

	return nil
}

// Ensure that HMACKeyGenParams implements the KeyGenerator interface.
var _ KeyGenerator = &RsaHashedKeyGenParams{}

// *GenerateKey implements the CryptoKeyPairGenerator interface for RsaHashedKeyGenParams, and generates
// a new RSA key pair.
//
//nolint:funlen
func (r *RsaHashedKeyGenParams) GenerateKey(
	extractable bool,
	keyUsages []CryptoKeyUsage,
) (CryptoKeyGenerationResult, error) {
	var (
		isSSAPKCS1v15 = strings.EqualFold(r.Name, RSASsaPkcs1v15)
		isPSS         = strings.EqualFold(r.Name, RSAPss)
		isOAEP        = strings.EqualFold(r.Name, RSAOaep)
	)

	if !isSSAPKCS1v15 && !isPSS && !isOAEP {
		return nil, NewError(ImplementationError, "unsupported algorithm name")
	}

	// 1.
	for _, usage := range keyUsages {
		if strings.EqualFold(r.Name, RSAOaep) {
			switch usage {
			case EncryptCryptoKeyUsage, DecryptCryptoKeyUsage, WrapKeyCryptoKeyUsage, UnwrapKeyCryptoKeyUsage:
				continue
			default:
				return nil, NewError(SyntaxError, "invalid key usage")
			}
		} else {
			switch usage {
			case SignCryptoKeyUsage, VerifyCryptoKeyUsage:
				continue
			default:
				return nil, NewError(SyntaxError, "invalid key usage")
			}
		}
	}

	// 2.
	keyPair, err := rsa.GenerateKey(rand.Reader, int(r.ModulusLength))
	if err != nil {
		// 3.
		return nil, NewError(OperationError, "failed to generate RSA key pair")
	}

	// 4. 5. 6. 7. 8.
	algorithm := RsaHashedKeyAlgorithm{}
	algorithm.Algorithm.Name = r.Name
	algorithm.ModulusLength = r.ModulusLength
	algorithm.PublicExponent = r.PublicExponent
	algorithm.Hash = KeyAlgorithm{Algorithm{Name: r.Hash}}

	// 9. 10. 11. 12.
	publicKey := CryptoKey{}
	publicKey.Type = PublicCryptoKeyType
	publicKey.Algorithm = algorithm
	publicKey.Extractable = true

	// 13.
	var publicKeyUsages []CryptoKeyUsage
	switch r.Name {
	case RSASsaPkcs1v15, RSAPss:
		publicKeyUsages = []CryptoKeyUsage{VerifyCryptoKeyUsage}
	case RSAOaep:
		publicKeyUsages = []CryptoKeyUsage{EncryptCryptoKeyUsage, WrapKeyCryptoKeyUsage}
	default:
		return nil, NewError(ImplementationError, "unsupported algorithm name")
	}
	publicKey.Usages = UsageIntersection(keyUsages, publicKeyUsages)
	publicKey.handle = keyPair.Public()

	// 14. 15. 16. 17.
	privateKey := CryptoKey{}
	privateKey.Type = PrivateCryptoKeyType
	privateKey.Algorithm = algorithm
	privateKey.Extractable = extractable

	// 18.
	var privateKeyUsages []CryptoKeyUsage
	switch r.Name {
	case RSASsaPkcs1v15, RSAPss:
		privateKeyUsages = []CryptoKeyUsage{SignCryptoKeyUsage}
	case RSAOaep:
		privateKeyUsages = []CryptoKeyUsage{DecryptCryptoKeyUsage, UnwrapKeyCryptoKeyUsage}
	default:
		return nil, NewError(ImplementationError, "unsupported algorithm name")
	}
	privateKey.Usages = UsageIntersection(keyUsages, privateKeyUsages)
	privateKey.handle = *keyPair

	// We apply the generateKey 8. step here, as we return a goja.Value
	// instead of a CryptoKey(Pair).
	if privateKey.Usages == nil || len(privateKey.Usages) == 0 {
		return nil, NewError(SyntaxError, "the keyUsages argument must contain at least one valid usage for the algorithm")
	}

	// 19. 20. 21.
	result := CryptoKeyPair{
		PrivateKey: &privateKey,
		PublicKey:  &publicKey,
	}

	// 22.
	return &result, nil
}

// Ensure that rsaSignerVerifier implements SignerVerifier interface
var _ SignerVerifier = rsaSignerVerifier{}

type rsaSignerVerifier struct{}

// RSASSA-PKSCv1_5 Sign .
func (rsaSignerVerifier) Sign(key CryptoKey, data []byte) ([]byte, error) {
	// 1.
	if key.Type != PrivateCryptoKeyType {
		return nil, NewError(InvalidAccessError, "key is not a valid "+RSASsaPkcs1v15+" private key")
	}

	k, ok := key.handle.(rsa.PrivateKey)
	if !ok {
		return nil, NewError(InvalidAccessError, "key is not a valid "+RSASsaPkcs1v15+" private key")
	}

	alg, ok := key.Algorithm.(RsaHashedKeyAlgorithm)
	if !ok {
		return nil, NewError(NotSupportedError, "unsupported hash algorithm")
	}

	hash := alg.Hash.Name
	hashFn, ok := getHashFn(hash)
	if !ok {
		return nil, NewError(NotSupportedError, "unsupported hash algorithm: "+hash)
	}

	cryptoHash, ok := getCryptoHash(hash)
	if !ok {
		return nil, NewError(NotSupportedError, "unsupported hash algorithm: "+hash)
	}

	hasher := hashFn()
	hasher.Write(data)

	// 2.
	s, err := rsa.SignPKCS1v15(rand.Reader, &k, cryptoHash, hasher.Sum(nil))

	// 3.
	if err != nil {
		return nil, NewError(OperationError, "unable to sign data:"+err.Error())
	}

	// 4.
	signature := s

	// 5.
	return signature, nil
}

func (rsaSignerVerifier) Verify(key CryptoKey, signature, dataToVerify []byte) (bool, error) {
	// 1.
	if key.Type != PublicCryptoKeyType {
		return false, NewError(InvalidAccessError, "key is not a valid RSASSA-PCKS1v1_5 public key")
	}

	k, ok := key.handle.(*rsa.PublicKey)
	if !ok {
		return false, NewError(InvalidAccessError, "key is not a valid RSASSA-PCKS1v1_5 public key")
	}

	// 2.
	alg, ok := key.Algorithm.(RsaHashedKeyAlgorithm)
	if !ok {
		return false, NewError(NotSupportedError, "unsupported hash algorithm")
	}

	hash := alg.Hash.Name

	hashFn, ok := getHashFn(hash)
	if !ok {
		return false, NewError(NotSupportedError, "unsupported hash algorithm: "+hash)
	}

	hasher := hashFn()
	hasher.Write(dataToVerify)

	cryptoHash, _ := getCryptoHash(hash)
	verifyErr := rsa.VerifyPKCS1v15(k, cryptoHash, hasher.Sum(nil), signature)

	// 3.
	if verifyErr != nil {
		return false, nil
	}

	return true, nil
}

// Ensure that RSAPssParams implements SignerVerifier interface
var _ SignerVerifier = &RSAPssParams{}

func newRSAPssParams(rt *sobek.Runtime, normalized Algorithm, params sobek.Value) (*RSAPssParams, error) {
	saltLength, err := traverseObject(rt, params, "saltLength")
	if err != nil {
		return nil, NewError(SyntaxError, "could not get hash from algorithm parameter")
	}

	return &RSAPssParams{
		Name:       normalized.Name,
		SaltLength: int(saltLength.ToInteger()),
	}, nil
}

func (rsaParams *RSAPssParams) Sign(key CryptoKey, data []byte) ([]byte, error) {
	// 1.
	if key.Type != PrivateCryptoKeyType {
		return nil, NewError(InvalidAccessError, "key is not a valid"+RSAPss+"private key")
	}

	k, ok := key.handle.(rsa.PrivateKey)
	if !ok {
		return nil, NewError(InvalidAccessError, "key is not a valid "+RSAPss+" private key")
	}

	alg, ok := key.Algorithm.(RsaHashedKeyAlgorithm)
	if !ok {
		return nil, NewError(NotSupportedError, "unsupported hash algorithm")
	}

	hash := alg.Hash.Name
	hashFn, ok := getHashFn(hash)
	if !ok {
		return nil, NewError(NotSupportedError, "unsupported hash algorithm: "+hash)
	}

	hasher := hashFn()
	hasher.Write(data)

	cryptoHash, ok := getCryptoHash(hash)
	if !ok {
		return nil, NewError(NotSupportedError, "unsupported hash algorithm: "+hash)
	}

	// 2.
	opts := rsa.PSSOptions{
		SaltLength: rsaParams.SaltLength,
		Hash:       cryptoHash,
	}
	s, err := rsa.SignPSS(rand.Reader, &k, cryptoHash, hasher.Sum(nil), &opts)

	// 3.
	if err != nil {
		return nil, NewError(OperationError, "unable to sign data:"+err.Error())
	}

	// 4.
	signature := s

	// 5.
	return signature, nil
}

func (rsaParams *RSAPssParams) Verify(key CryptoKey, signature, dataToVerify []byte) (bool, error) {
	// 1.
	if key.Type != PublicCryptoKeyType {
		return false, NewError(InvalidAccessError, "key is not a valid RSA-PSS public key")
	}

	k, ok := key.handle.(*rsa.PublicKey)
	if !ok {
		return false, NewError(InvalidAccessError, "key is not a valid RSA-PSS public key")
	}

	// 2.
	alg, ok := key.Algorithm.(RsaHashedKeyAlgorithm)
	if !ok {
		return false, NewError(NotSupportedError, "unsupported hash algorithm")
	}

	hash := alg.Hash.Name

	hashFn, ok := getHashFn(hash)
	if !ok {
		return false, NewError(NotSupportedError, "unsupported hash algorithm: "+hash)
	}

	hasher := hashFn()
	hasher.Write(dataToVerify)

	cryptoHash, _ := getCryptoHash(hash)
    opts := rsa.PSSOptions{SaltLength: rsaParams.SaltLength, Hash: 0}
    verifyErr := rsa.VerifyPSS(k, cryptoHash, hasher.Sum(nil), signature, &opts)

	// 3.
	if verifyErr != nil {
		return false, nil
	}

	return true, nil
}
