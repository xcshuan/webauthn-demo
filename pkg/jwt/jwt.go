package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/golang-jwt/jwt"
)

// JWT a mock interface to JWT signing
type JWT struct {
	// RsaPrivateKey private key to sign JWT claims
	RsaPrivateKey *rsa.PrivateKey
	// RsaPubkey is the public key of the private key, used to verify a signature
	RsaPubkey *rsa.PublicKey

	// for JWKS functions
	n string // rsa public key modulus Base64urlUInt-encoded
	e string // public key exponent Base64urlUInt-encoded
}

// NewJWT returns an instance of the JWT type. Will fail if `privateKeyPath` cannot be read or a private key parsed.
func NewJWT(privateKeyPath string) (*JWT, error) {
	p := JWT{}

	pemData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	var block *pem.Block
	var rest = pemData
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("no private key found in PEM file")
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			break
		}
	}

	var privatekey *rsa.PrivateKey
	if strings.Contains(block.Type, "RSA ") {
		privatekey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			rsapk, ok := pk.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("private key is not RSA")
			}
			privatekey = rsapk
		}
	}
	if err != nil {
		return nil, err
	}
	p.RsaPrivateKey = privatekey
	p.RsaPubkey = &privatekey.PublicKey

	p.n, p.e = PubToB64UrlUint(p.RsaPubkey)

	return &p, nil
}

// NewToken just create a token without signing it into an accessToken. See SignClaims for the latter.
func (m *JWT) NewToken(data jwt.MapClaims, expires time.Time, keyID string) *jwt.Token {
	claims := jwt.MapClaims{}
	claims["exp"] = expires.Unix() // well-known claim
	claims["authorization"] = true

	for i, v := range data {
		claims[i] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	token.Header["type"] = "at+jwt"

	return token
}

// SignClaims mock a token issuer and return an accessToken suitable for inclusion in a Bearer Authorization header.
func (m *JWT) SignClaims(data jwt.MapClaims, expires time.Time) string {
	token := m.NewToken(data, expires, "1")
	accessToken, err := token.SignedString(m.RsaPrivateKey) // must be same alg as used by jwt.NewWithClaims()
	if err != nil {
		panic("signing JWT token: " + err.Error())
	}
	return accessToken
}

// Returns the integer in big-endian byte order
func int64ToBytes(s int64) []byte {
	u := uint64(s)
	l := int(unsafe.Sizeof(u))
	b := make([]byte, l)
	for i := 0; i < l; i++ {
		b[i] = byte((u >> uint(8*(l-i-1))) & 0xff)
	}
	return b
}

// Invert int64ToBytes
func bytesToInt64(b []byte) (int64, error) {
	u := uint64(0)
	l := int(unsafe.Sizeof(u))
	if len(b) != l {
		return 0, errors.New("bad length for input")
	}
	for i := 0; i < l; i++ {
		u |= uint64(b[i]) << uint(8*(l-i-1))
	}
	return int64(u), nil
}

// B64UrlUintToPub converts Base64UrlUint-encoded strings to an RSA public key
func B64UrlUintToPub(ns, es string) (*rsa.PublicKey, error) {
	enc := base64.RawURLEncoding
	pk := rsa.PublicKey{}

	buf := make([]byte, 4096)

	// N
	n, err := enc.Decode(buf, []byte(ns))
	if err != nil {
		return nil, err
	}
	pk.N = &big.Int{}
	pk.N.SetBytes(buf[0:n])

	// E
	n, err = enc.Decode(buf, []byte(es))
	if err != nil {
		return nil, err
	}
	pke64, err := bytesToInt64(buf[0:n])
	if err != nil {
		return nil, err
	}
	pk.E = int(pke64)

	return &pk, nil
}

// PubToB64UrlUint converts RSA public key to Base64UrlUint-encoded modulus and exponent strings, for testing
func PubToB64UrlUint(pk *rsa.PublicKey) (encN, encE string) {
	if pk == nil {
		return "", ""
	}

	enc := base64.RawURLEncoding

	N := pk.N
	E := pk.E // int

	bN := N.Bytes()
	bE := int64ToBytes(int64(E))

	lN := enc.EncodedLen(len(bN))
	lE := enc.EncodedLen(len(bE))

	rN := make([]byte, lN)
	rE := make([]byte, lE)

	enc.Encode(rN, bN)
	enc.Encode(rE, bE)

	return string(rN), string(rE)
}
