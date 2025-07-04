package utils

import (
	"errors"

	"github.com/gin-gonic/gin"
)

func GetClaimsCtx(c *gin.Context) (*JWTClaims, error) {
	ctxClaims, ok := c.Get("claims")
	if !ok {
		return nil, errors.New("user context not found")
	}

	claims, ok := ctxClaims.(*JWTClaims)
	if !ok {
		return nil, errors.New("convert user context to JWTClaims failed")
	}

	return claims, nil
}
