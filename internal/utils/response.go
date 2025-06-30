package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func ResponseSuccess(c *gin.Context, data interface{}, msg *string, code ...int) {
	responseCode := http.StatusOK
	if len(code) > 0 {
		responseCode = code[0]
	}

	responseMsg := "Success"
	if msg != nil {
		responseMsg = *msg
	}

	c.JSON(responseCode, gin.H{
		"success": true,
		"msg":     responseMsg,
		"data":    data,
	})
}

func ResponseError(c *gin.Context, err error, code ...int) {
	responseCode := http.StatusInternalServerError
	if len(code) > 0 {
		responseCode = code[0]
	}

	c.JSON(responseCode, gin.H{
		"success": false,
		"msg":     err.Error(),
	})
}
