package jwtmanager

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTPair struct {
	AccessToken     string        `json:"access_token"`
	AccessTokenExp  time.Duration `json:"access_token_exp"`
	RefreshToken    string        `json:"refresh_token"`
	RefreshTokenExp time.Duration `json:"refresh_token_exp"`
}

type GenerateJWTPairData struct {
	AccessMethod  jwt.SigningMethod
	AccessSecret  []byte
	AccessClaims  jwt.MapClaims
	AccessExpiry  time.Duration
	RefreshMethod jwt.SigningMethod
	RefreshSecret []byte
	RefreshClaims jwt.MapClaims
	RefreshExpiry time.Duration
}

func GenerateJWTPair(data GenerateJWTPairData) (*JWTPair, error) {
	now := time.Now()

	data.AccessClaims["exp"] = now.Add(data.AccessExpiry).Unix()
	accessToken := jwt.NewWithClaims(data.AccessMethod, data.AccessClaims)
	accessTokenString, err := accessToken.SignedString(data.AccessSecret)
	if err != nil {
		return nil, err
	}

	data.RefreshClaims["exp"] = now.Add(data.RefreshExpiry).Unix()
	refreshToken := jwt.NewWithClaims(data.RefreshMethod, data.RefreshClaims)
	refreshTokenString, err := refreshToken.SignedString(data.RefreshSecret)
	if err != nil {
		return nil, err
	}

	return &JWTPair{
		AccessToken:     accessTokenString,
		AccessTokenExp:  data.AccessExpiry,
		RefreshToken:    refreshTokenString,
		RefreshTokenExp: data.RefreshExpiry,
	}, nil
}

func DecodeJWT(tokenString string, secret []byte) (jwt.MapClaims, error) {
	parsedToken, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, err
	}

	return claims, nil
}
