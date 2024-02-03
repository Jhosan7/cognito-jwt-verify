# Cognito JWT Verifier

This is a simple library to verify JWT tokens issued by AWS Cognito. It is written in Go and is based on the [aws-jwt-verify](https://github.com/awslabs/aws-jwt-verify) library.

## Usage

```go
package main

import (
    "fmt"
    "github.com/jhosan7/cognito-jwt-verify"
)

func main() {
    cognitoConfig := cognitoJwtVerify.Config{
        UserPoolId: "eu-west-1_XXXX",
        ClientId:   "xxxxx...",
        TokenUse:   "access", // id or access, if not set, it will not check the token use
    }
    
    verify, err := cognitoJwtVerify.Create(cognitoConfig)
    if err != nil {
        fmt.Println(err)
        return
    }
    
    payload, err := verify.Verify("eyJraW...")
    if err != nil {
        fmt.Printf("Error: %s\n", err)
        return
    }
    
    fmt.Println(payload)
}
```
