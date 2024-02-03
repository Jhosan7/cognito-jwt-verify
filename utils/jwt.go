package utils

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"math/big"
	"strings"
)

type JwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type JwtPayload struct {
	Exp      int64  `json:"exp"`
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Aud      string `json:"aud"`
	Iat      int64  `json:"iat"`
	Scope    string `json:"scope"`
	Jti      string `json:"jti"`
	TokenUse string `json:"token_use"`
}

type DecomposedJwt struct {
	Header       JwtHeader
	HeaderB64    string
	Payload      JwtPayload
	PayloadB64   string
	SignatureB64 string
}

func base64Decode(b64 string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func decodeJwtHeader(headerB64 string) (JwtHeader, error) {
	headerJson, err := base64Decode(headerB64)
	if err != nil {
		return JwtHeader{}, err
	}

	var header JwtHeader
	err = json.Unmarshal([]byte(headerJson), &header)
	if err != nil {
		return JwtHeader{}, err
	}

	return header, nil
}

func DecomposeUnverifiedJwt(jwt string) (DecomposedJwt, error) {
	if jwt == "" {
		return DecomposedJwt{}, fmt.Errorf("jwt is empty")
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return DecomposedJwt{}, fmt.Errorf("JWT string does not consist of exactly 3 parts (header, payload, signature)")
	}

	headerB64 := parts[0]
	payloadB64 := parts[1]
	signatureB64 := parts[2]

	header, err := decodeJwtHeader(headerB64)
	if err != nil {
		return DecomposedJwt{}, err
	}

	payloadJson, err := base64Decode(payloadB64)
	if err != nil {
		return DecomposedJwt{}, err
	}

	var payload JwtPayload
	err = json.Unmarshal([]byte(payloadJson), &payload)
	if err != nil {
		return DecomposedJwt{}, err
	}

	return DecomposedJwt{
		Header:       header,
		HeaderB64:    headerB64,
		Payload:      payload,
		PayloadB64:   payloadB64,
		SignatureB64: signatureB64,
	}, nil
}

func VerifyDecomposedJwt(decomposeUnverifiedJwt DecomposedJwt, issuer string, tokenUse string, alg string) error {
	if decomposeUnverifiedJwt.Header.Kid == "" {
		return fmt.Errorf("kid is empty")
	}

	if decomposeUnverifiedJwt.Payload.Iss != issuer {
		return fmt.Errorf("iss claim does not match the issuer")
	}

	if tokenUse != "" && decomposeUnverifiedJwt.Payload.TokenUse != tokenUse {
		return fmt.Errorf("aud claim does not match the token use")
	}

	if decomposeUnverifiedJwt.Header.Alg != alg {
		return fmt.Errorf("alg claim does not match the algorithm")
	}

	return nil
}

func getPublicKey(jwk JwkWithKid) (*rsa.PublicKey, error) {
	decodedN, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}

	decodedE, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(decodedN),
		E: int(new(big.Int).SetBytes(decodedE).Int64()),
	}

	return publicKey, nil
}

func ValidateJwt(jwtToken string, jwk JwkWithKid) (*jwt.Token, error) {
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		publicKey, err := getPublicKey(jwk)
		if err != nil {
			return nil, err
		}

		if token.Method.Alg() != "RS256" {
			return nil, errors.New("invalid signing algorithm")
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return token, nil
}
