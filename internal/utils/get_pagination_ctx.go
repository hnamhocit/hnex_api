package utils

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"
)

func GetPaginationCtx(c *gin.Context) (int, int, error) {
	limitStr := c.DefaultQuery("limit", "20")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		return 0, 0, errors.New("Invalid limit parameter")
	}

	pageStr := c.DefaultQuery("page", "1")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page <= 0 {
		return 0, 0, errors.New("Invalid page parameter")
	}

	return limit, page, nil
}
