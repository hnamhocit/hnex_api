package middlewares

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"hnex.com/internal/services"
	"hnex.com/internal/utils"
)

func AccessTokenMiddleware(banService *services.BanService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if authorization == "" {
			utils.ResponseError(c, errors.New("unauthorized"), http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authorization, "Bearer ") {
			utils.ResponseError(c, errors.New("invalid header format"), http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authorization, "Bearer ")
		claims, err := utils.VerifyToken(token, "JWT_ACCESS_SECRET")
		if err != nil {
			utils.ResponseError(c, err, http.StatusUnauthorized)
			return
		}

		ctx := c.Request.Context()
		bannedUser, err := banService.GetBannedUser(ctx, claims.Sub)
		if err != nil {
			utils.ResponseError(c, err)
			return
		}

		if bannedUser != nil {
			utils.ResponseError(c, errors.New("account is banned"), http.StatusForbidden)
			return
		}

		c.Set("user", claims)

		c.Next()
	}
}
