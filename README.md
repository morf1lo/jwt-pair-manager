## JWT Pair Manager

```
go get github.com/morf1lo/jwt-pair-manager
```

### Example
```go
package main

import (
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/morf1lo/jwt-pair-manager"
)

func main() {
	data := jwtmanager.GenerateJWTPairData{
AccessMethod: jwt.SigningMethodHS256,
AccessSecret: []byte("super_mega_ACCESS_secret"),
AccessClaims: jwt.MapClaims{
	"id": 123,
	"role": "user",
},
AccessExpiry: time.Hour,
RefreshMethod: jwt.SigningMethodHS256,
RefreshSecret: []byte("super_mega_REFRESH_secret"),
RefreshClaims: jwt.MapClaims{
	"id": 123,
},
RefreshExpiry: time.Hour * 24 * 3,
}

    jwtPair, err := jwtmanager.GenerateJWTPair(data)
    if err != nil {
        // Handle error
    }

    fmt.Printf("Access Token: %s\n", jwtPair.AccessToken)
    fmt.Printf("Access Expires at: %v\n", jwtPair.AccessTokenExp)
    fmt.Printf("Refresh Token: %s\n", jwtPair.RefreshToken)
    fmt.Printf("Refresh Expires at: %v\n", jwtPair.RefreshTokenExp)
}
```
