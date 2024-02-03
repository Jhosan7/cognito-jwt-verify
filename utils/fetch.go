package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type JwkWithKid struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type Jwks struct {
	Keys []JwkWithKid `json:"keys"`
}

func fetchJwks(jwksUri string) (*Jwks, error) {
	res, err := http.Get(jwksUri)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch JWKS: %s", res.Status)
	}

	jwks, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var jwksStruct Jwks
	err = json.Unmarshal(jwks, &jwksStruct)
	if err != nil {
		return nil, err
	}

	return &jwksStruct, nil
}

func fetchJwk(jwksUri string, decomposedJwt DecomposedJwt) (JwkWithKid, error) {
	jwks, err := fetchJwks(jwksUri)
	if err != nil {
		return JwkWithKid{}, err
	}

	for _, jwk := range jwks.Keys {
		if jwk.Kid == decomposedJwt.Header.Kid {
			return jwk, nil
		}
	}

	return JwkWithKid{}, fmt.Errorf("jwk not found for kid: %s", decomposedJwt.Header.Kid)
}

func GetJwk(decomposeUnverifiedJwt DecomposedJwt, jwksUri string, cache *Cache) (JwkWithKid, error) {
	var jwk JwkWithKid
	jwk, ok := cache.Get(decomposeUnverifiedJwt.Header.Kid)
	if ok {
		return jwk, nil
	}

	jwk, err := fetchJwk(jwksUri, decomposeUnverifiedJwt)
	if err != nil {
		return JwkWithKid{}, err
	}
	cache.Add(decomposeUnverifiedJwt.Header.Kid, jwk)

	return jwk, nil
}
