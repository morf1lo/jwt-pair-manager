package jwtmanager

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

var (
	accessSecret  = []byte("super_mega_ACCESS_secret")
	refreshSecret = []byte("super_mega_REFRESH_secret")

	userID = 123
	userRole = "user"
)

func TestGenerateJWTPair(t *testing.T) {
	data := GenerateJWTPairData{
		AccessMethod: jwt.SigningMethodHS256,
		AccessSecret: accessSecret,
		AccessClaims: jwt.MapClaims{
			"id": userID,
			"role": userRole,
		},
		AccessExpiry: time.Hour,
		RefreshMethod: jwt.SigningMethodHS256,
		RefreshSecret: refreshSecret,
		RefreshClaims: jwt.MapClaims{
			"id": userID,
		},
		RefreshExpiry: time.Hour * 24 * 3,
	}

	jwtPair, err := GenerateJWTPair(data)
	assert.NoError(t, err)
	assert.NotEmpty(t, jwtPair.AccessToken)
	assert.NotEmpty(t, jwtPair.RefreshToken)
}

func TestDecodeJWT_Valid(t *testing.T) {
	claims := jwt.MapClaims{
		"id": userID,
		"role": userRole,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(accessSecret)

	decodedClaims, err := DecodeJWT(tokenString, accessSecret)
	assert.NoError(t, err)
	assert.Equal(t, float64(userID), decodedClaims["id"])
	assert.Equal(t, userRole, decodedClaims["role"])
}

func TestDecodeJWT_Invalid(t *testing.T) {
	_, err := DecodeJWT("invalid.token.here", refreshSecret)
	assert.Error(t, err)
}

func TestDecodeJWT_Expired(t *testing.T) {
	claims := jwt.MapClaims{
		"id": userID,
		"role": userID,
		"exp": time.Now().Add(-time.Second).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(refreshSecret)

	_, err := DecodeJWT(tokenString, refreshSecret)
	assert.Error(t, err)
}
