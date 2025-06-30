package utils

import (
	"errors"

	"github.com/gin-gonic/gin"
)

func GetUserCtx(c *gin.Context) (*JWTClaims, error) {
	ctxClaims, ok := c.Get("user")
	if !ok {
		return nil, errors.New("User context not found!")
	}

	claims, ok := ctxClaims.(*JWTClaims)
	if !ok {
		return nil, errors.New("Convert user context to JWTClaims failed")
	}

	return claims, nil
}
