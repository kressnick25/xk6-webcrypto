package webcrypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

const (
	// JWKECKeyType represents the elliptic curve key type.
	JWKECKeyType = "EC"

	// JWKOctKeyType represents the symmetric key type.
	JWKOctKeyType = "oct"

    JWKRsaKeyType = "RSA"
)

// JsonWebKey represents a JSON Web Key (JsonWebKey) key.
type JsonWebKey map[string]interface{} //nolint:stylecheck,revive // we name this type JsonWebKey to match the spec

// Set sets a key-value pair in the JWK.
func (jwk *JsonWebKey) Set(key string, value interface{}) {
	(*jwk)[key] = value
}

// symmetricJWK represents a symmetric JWK key.
// It is used to unmarshal symmetric keys from JWK format.
type symmetricJWK struct {
	Kty string `json:"kty"`
	K   string `json:"k"`
}

func (jwk *symmetricJWK) validate() error {
	if jwk.Kty != JWKOctKeyType {
		return fmt.Errorf("invalid key type: %s", jwk.Kty)
	}

	if jwk.K == "" {
		return errors.New("key (k) is required")
	}

	return nil
}

// extractSymmetricJWK extracts the symmetric key from a given JWK key (JSON data).
func extractSymmetricJWK(jsonKeyData []byte) ([]byte, error) {
	sk := symmetricJWK{}
	if err := json.Unmarshal(jsonKeyData, &sk); err != nil {
		return nil, fmt.Errorf("failed to parse symmetric JWK: %w", err)
	}

	if err := sk.validate(); err != nil {
		return nil, fmt.Errorf("invalid symmetric JWK: %w", err)
	}

	skBytes, err := base64URLDecode(sk.K)
	if err != nil {
		return nil, fmt.Errorf("failed to decode symmetric key: %w", err)
	}

	return skBytes, nil
}

// exportSymmetricJWK exports a symmetric key as a map of JWK key parameters.
func exportSymmetricJWK(key *CryptoKey) (*JsonWebKey, error) {
	rawKey, ok := key.handle.([]byte)
	if !ok {
		return nil, errors.New("key's handle isn't a byte slice")
	}

	// wrap result into the object that is expected to be returned
	exported := &JsonWebKey{}

	exported.Set("k", base64URLEncode(rawKey))
	exported.Set("kty", JWKOctKeyType)
	exported.Set("ext", key.Extractable)
	exported.Set("key_ops", key.Usages)

	algV, err := extractAlg(key.Algorithm, len(rawKey))
	if err != nil {
		return nil, fmt.Errorf("failed to extract algorithm: %w", err)
	}
	exported.Set("alg", algV)

	return exported, nil
}

func extractAlg(inAlg any, keyLen int) (string, error) {
	switch alg := inAlg.(type) {
	case hasHash:
		v := alg.hash()
		if len(v) < 4 {
			return "", errors.New("length of hash algorithm is less than 4: " + v)
		}
		return "HS" + v[4:], nil
	case hasAlg:
		v := alg.alg()
		if len(v) < 4 {
			return "", errors.New("length of named algorithm is less than 4: " + v)
		}

		return fmt.Sprintf("A%d%s", (8 * keyLen), v[4:]), nil
	default:
		return "", fmt.Errorf("unsupported algorithm: %v", inAlg)
	}
}

// ecJWK represents an EC JWK key.
// It is used to unmarshal ECDSA and ECDH keys to and from JWK format.
type ecJWK struct {
	// Key type
	Kty string `json:"kty"`
	// Canonical Curve
	Crv string `json:"crv"`
	// X coordinate
	X string `json:"x"`
	// Y coordinate
	Y string `json:"y"`
	// Private scalar
	D string `json:"d"`
}

func (jwk *ecJWK) validate() error {
	if jwk.Kty != JWKECKeyType {
		return fmt.Errorf("invalid key type: %s", jwk.Kty)
	}

	if jwk.Crv == "" {
		return errors.New("curve is required")
	}

	if jwk.X == "" {
		return errors.New("coordinate X is required")
	}

	if jwk.Y == "" {
		return errors.New("coordinate Y is required")
	}

	return nil
}

// encodeCurveBigInt encodes the private scalar D of an ECDSA key with padding.
func encodeCurveBigInt(data *big.Int, curveBits int) string {
	// Determine the expected byte length for the curve
	byteLength := curveBits / 8
	// Add one more byte if the bits are not a multiple of 8
	if curveBits%8 != 0 {
		byteLength++
	}

	dBytes := data.Bytes()
	dPadded := padLeft(dBytes, byteLength) // Pad if necessary

	return base64URLEncode(dPadded)
}

// padLeft pads the byte slice with zeros to the left to ensure it has a specific length.
func padLeft(bytes []byte, size int) []byte {
	padding := make([]byte, size-len(bytes))
	return append(padding, bytes...) //nolint:makezero // we need to pad with zeros
}

func exportECJWK(key *CryptoKey) (interface{}, error) {
	exported := &JsonWebKey{}
	exported.Set("kty", JWKECKeyType)

	var x, y, d *big.Int
	var curveParams *elliptic.CurveParams

	switch k := key.handle.(type) {
	case *ecdsa.PrivateKey:
		x = k.X
		y = k.Y
		d = k.D
		curveParams = k.Curve.Params()
	case *ecdsa.PublicKey:
		x = k.X
		y = k.Y
		curveParams = k.Curve.Params()
	case *ecdh.PrivateKey:
		ecdsaKey, err := convertECDHtoECDSAKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to convert ECDH key to ECDSA key: %w", err)
		}

		x = ecdsaKey.X
		y = ecdsaKey.Y
		d = ecdsaKey.D
		curveParams = ecdsaKey.Curve.Params()
	case *ecdh.PublicKey:
		ecdsaKey, err := convertPublicECDHtoECDSA(k)
		if err != nil {
			return nil, fmt.Errorf("failed to convert ECDH key to ECDSA key: %w", err)
		}

		x = ecdsaKey.X
		y = ecdsaKey.Y
		curveParams = ecdsaKey.Curve.Params()
	default:
		return nil, errors.New("key's handle isn't an ECDSA/ECDH public/private key")
	}

	exported.Set("crv", curveParams.Name)
	curveBits := curveParams.BitSize

	exported.Set("x", base64URLEncode(x.Bytes()))
	exported.Set("y", base64URLEncode(y.Bytes()))

	if d != nil {
		exported.Set("d", encodeCurveBigInt(d, curveBits))
	}

	return exported, nil
}

func importECDSAJWK(_ EllipticCurveKind, jsonKeyData []byte) (any, CryptoKeyType, error) {
	var jwkKey ecJWK
	if err := json.Unmarshal(jsonKeyData, &jwkKey); err != nil {
		return nil, UnknownCryptoKeyType, fmt.Errorf("failed to parse input as EC JWK key: %w", err)
	}

	if err := jwkKey.validate(); err != nil {
		return nil, UnknownCryptoKeyType, fmt.Errorf("invalid EC JWK key: %w", err)
	}

	crv, err := pickEllipticCurve(jwkKey.Crv)
	if err != nil {
		return nil, UnknownCryptoKeyType, fmt.Errorf("failed to parse elliptic curve: %w", err)
	}

	x, err := base64URLDecode(jwkKey.X)
	if err != nil {
		return nil, UnknownCryptoKeyType, fmt.Errorf("failed to decode X coordinate: %w", err)
	}

	y, err := base64URLDecode(jwkKey.Y)
	if err != nil {
		return nil, UnknownCryptoKeyType, fmt.Errorf("failed to decode Y coordinate: %w", err)
	}

	pk := &ecdsa.PublicKey{
		Curve: crv,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}

	// if the key is a public key, return it
	if jwkKey.D == "" {
		return pk, PublicCryptoKeyType, nil
	}

	d, err := base64URLDecode(jwkKey.D)
	if err != nil {
		return nil, UnknownCryptoKeyType, fmt.Errorf("failed to decode D: %w", err)
	}

	return &ecdsa.PrivateKey{
		PublicKey: *pk,
		D:         new(big.Int).SetBytes(d),
	}, PrivateCryptoKeyType, nil
}

func importECDHJWK(_ EllipticCurveKind, jsonKeyData []byte) (any, CryptoKeyType, error) {
	// first we do try to parse the key as ECDSA key
	key, _, err := importECDSAJWK(EllipticCurveKindP256, jsonKeyData)
	if err != nil {
		return nil, UnknownCryptoKeyType, fmt.Errorf("failed to parse input as ECDH key: %w", err)
	}

	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		ecdhKey, err := key.ECDH()
		if err != nil {
			return nil, UnknownCryptoKeyType, fmt.Errorf("failed to convert ECDSA key to ECDH key: %w", err)
		}

		return ecdhKey, PrivateCryptoKeyType, nil
	case *ecdsa.PublicKey:
		ecdhKey, err := key.ECDH()
		if err != nil {
			return nil, UnknownCryptoKeyType, fmt.Errorf("failed to convert ECDSA key to ECDH key: %w", err)
		}

		return ecdhKey, PublicCryptoKeyType, nil
	default:
		return nil, UnknownCryptoKeyType, errors.New("input isn't a valid ECDH key")
	}
}


func exportRsaJwk(ck *CryptoKey) (interface{}, error) {
    exported := &JsonWebKey{}
    exported.Set("kty", JWKRsaKeyType)

    alg := ck.Algorithm.(RsaHashedKeyAlgorithm)
    switch alg.Hash.Name {
    case SHA1:
        exported.Set("alg", "RS1")
    case SHA256:
        exported.Set("alg", "RS256")
    case SHA384:
        exported.Set("alg", "RS384")
    case SHA512:
        exported.Set("alg", "RS512")
    default:
        return nil, NewError(NotSupportedError, "unsupported RSA algorithm hash for JWK export")
    }

    // WebCrypto Standard defers to RFC 7518 for this section
    // RFC 7518 section 6.3.1
    switch ck.Type {
    case PublicCryptoKeyType:
        key := ck.handle.(rsa.PublicKey)
        exported.Set("n", base64URLEncode(key.N.Bytes()))
        e := big.NewInt(int64(key.E))
        exported.Set("e", base64URLEncode(e.Bytes()))
    case PrivateCryptoKeyType:
        key := ck.handle.(rsa.PrivateKey)
        exported.Set("n", base64URLEncode(key.N.Bytes()))
        e := big.NewInt(int64(key.E))
        exported.Set("e", base64URLEncode(e.Bytes()))

        // RFC 7518 section 6.3.2
        exported.Set("d", base64URLEncode(key.D.Bytes()))
        exported.Set("p", base64URLEncode(key.Primes[0].Bytes()))
        exported.Set("q", base64URLEncode(key.Primes[1].Bytes()))

        key.Precompute()
        exported.Set("dp", base64URLEncode(key.Precomputed.Dp.Bytes()))
        exported.Set("dq", base64URLEncode(key.Precomputed.Dq.Bytes()))
        exported.Set("qi", base64URLEncode(key.Precomputed.Qinv.Bytes()))


        // RFC 7518 section 6.3.2.7
        if len(key.Primes) > 2 {
            encodedPrimes := make([]string, len(key.Primes))
            for i, prime := range key.Primes[1:] {
               encodedPrimes[i] = base64URLEncode(prime.Bytes())
            }
            exported.Set("oth", encodedPrimes)
        }
    default:
        return nil, NewError(InvalidAccessError, "invalid key type for RSA JWK")

    }

    exported.Set("key_opts", ck.Usages)
    exported.Set("ext", ck.Extractable)

    return exported, nil
}
