package middlewares

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"hnex.com/internal/services"
	"hnex.com/internal/utils"
)

func BanMiddleware(banService *services.BanService) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := utils.GetClaimsCtx(c)
		if err != nil {
			utils.ResponseError(c, err, http.StatusUnauthorized)
			return
		}

		ctx := c.Request.Context()
		ban, err := banService.Getban(ctx, claims.Sub)
		if err != nil {
			utils.ResponseError(c, err)
			return
		}

		if ban != nil {
			utils.ResponseError(c, errors.New("account has been banned"), http.StatusForbidden)
			return
		}

		c.Next()
	}
}
