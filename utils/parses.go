package utils

import (
	"fmt"
	"regexp"
)

func ParseUserPoolId(userPoolId string) (issuer string, jwksUri string, err error) {
	re := regexp.MustCompile(`^(?P<region>(\w+-)?\w+-\w+-\d+)_\w+$`)
	match := re.FindStringSubmatch(userPoolId)

	if match == nil {
		return "", "", fmt.Errorf("invalid user pool id: %s", userPoolId)
	}

	region := match[1]
	issuer = fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolId)
	jwksUri = fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolId)

	return issuer, jwksUri, nil
}
