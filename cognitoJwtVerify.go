package cognitoJwtVerify

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/logstraining/cognito-jwt-verify-go/utils"
)

type CognitoJwtVerifier struct {
	issuer   string
	jwksUri  string
	tokenUse string
	cache    *utils.Cache
}

type Config struct {
	UserPoolId string
	TokenUse   string
	ClientId   string
}

func Create(config Config) (CognitoJwtVerifier, error) {
	issuer, jwksUri, err := utils.ParseUserPoolId(config.UserPoolId)
	if err != nil {
		return CognitoJwtVerifier{}, err
	}

	return CognitoJwtVerifier{
		issuer:   issuer,
		jwksUri:  jwksUri,
		tokenUse: config.TokenUse,
		cache:    utils.NewCache(),
	}, nil
}

func (c CognitoJwtVerifier) Verify(token string) (jwt.Claims, error) {
	decomposeUnverifiedJwt, err := utils.DecomposeUnverifiedJwt(token)
	if err != nil {
		return nil, err
	}

	jwk, err := utils.GetJwk(decomposeUnverifiedJwt, c.jwksUri, c.cache)
	if err != nil {
		return nil, err
	}

	err = utils.VerifyDecomposedJwt(decomposeUnverifiedJwt, c.issuer, c.tokenUse, jwk.Alg)
	if err != nil {
		return nil, err
	}

	validToken, err := utils.ValidateJwt(token, jwk)
	if err != nil {
		return nil, err
	}

	return validToken.Claims, nil
}
