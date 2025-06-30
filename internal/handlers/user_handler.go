package handlers

import (
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
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	user, err := utils.GetUserCtx(c)
	if err != nil {
		utils.ResponseError(c, err, http.StatusNotFound)
		return
	}

	if err := h.Repo.UpdateFieldsById(user.Sub, payload); err != nil {
		utils.ResponseError(c, err, http.StatusNotFound)
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
}

func (h *UserHandler) GetUser(c *gin.Context) {
	id := c.Param("id")

	user, err := h.Repo.FindById(id)
	if err != nil {
		utils.ResponseError(c, err, http.StatusNotFound)
		return
	}

	utils.ResponseSuccess(c, user, nil)
}

func (h *UserHandler) GetProfile(c *gin.Context) {
	claims, err := utils.GetUserCtx(c)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	user, err := h.Repo.FindById(claims.Sub)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	utils.ResponseSuccess(c, user, nil)
}
