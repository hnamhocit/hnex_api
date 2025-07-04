package utils

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"hnex.com/internal/models"
)

type TokenParams struct {
	Id          string
	Role        models.Role
	CountryCode string
	Provider    string
}

type JWTClaims struct {
	Sub         string      `json:"sub"`
	Role        models.Role `json:"role"`
	CountryCode string      `json:"country_code"`
	Provider    string      `json:"provider"`
	jwt.RegisteredClaims
}

func GenerateTokens(params *TokenParams) (accessToken, refreshToken string, err error) {

	accessTokenSecret := []byte(os.Getenv("JWT_ACCESS_SECRET"))
	refreshTokenSecret := []byte(os.Getenv("JWT_REFRESH_SECRET"))

	JWT_ACCESS_EXPIRES_IN, err := strconv.Atoi(os.Getenv("JWT_ACCESS_EXPIRES_IN"))
	if err != nil {
		log.Fatal("Error parsing JWT_ACCESS_EXPIRES_IN")
	}

	JWT_REFRESH_EXPIRES_IN, err := strconv.Atoi(os.Getenv("JWT_REFRESH_EXPIRES_IN"))
	if err != nil {
		log.Fatal("Error parsing JWT_REFRESH_EXPIRES_IN")
	}

	accessClaims := &JWTClaims{
		Sub:         params.Id,
		Role:        params.Role,
		Provider:    params.Provider,
		CountryCode: params.CountryCode,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(JWT_ACCESS_EXPIRES_IN) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "hnex.api.com",
			Audience:  []string{"access", params.Provider},
		},
	}

	accessToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(accessTokenSecret)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	refreshClaims := &JWTClaims{
		Sub:         params.Id,
		Role:        params.Role,
		Provider:    params.Provider,
		CountryCode: params.CountryCode,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(JWT_REFRESH_EXPIRES_IN) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "hnex.api.com",
			Audience:  []string{"refresh", params.Provider},
		},
	}

	refreshToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(refreshTokenSecret)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

func VerifyToken(tokenString string, name string) (*JWTClaims, error) {
	secret := []byte(os.Getenv(name))

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("token parse error: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}
