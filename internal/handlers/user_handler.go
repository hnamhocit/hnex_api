package handlers

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	dtos "hnex.com/internal/dtos/user"
	"hnex.com/internal/repositories"
	"hnex.com/internal/utils"
)

type UserHandler struct {
	Repo *repositories.UserRepository
}

func (h *UserHandler) UpdateProfile(c *gin.Context) {
	var payload dtos.UpdateProfileDTO
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	user, err := utils.GetUserCtx(c)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	if err := h.Repo.UpdateFieldsById(user.Sub, payload); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
}

func (h *UserHandler) GetUser(c *gin.Context) {
	id := c.Param("id")

	user, err := h.Repo.FindById(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 1,
		"data": user,
	})
}

func (h *UserHandler) GetProfile(c *gin.Context) {
	user, ok := c.Get("user")
	if !ok {
		log.Println("User context not found")
		c.JSON(http.StatusUnauthorized, gin.H{"code": 0, "msg": "User context not found"})
		return
	}

	claims, ok := user.(*utils.JWTClaims)
	if !ok {
		log.Println("Convert user context to JWTClaims failed")
		c.JSON(http.StatusUnauthorized, gin.H{"code": 0, "msg": "Convert user context to JWTClaims failed"})
		return
	}

	user, err := h.Repo.FindById(claims.Sub)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 1,
		"data": user,
	})
}
