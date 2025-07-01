package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	dtos "hnex.com/internal/dtos/user"
	"hnex.com/internal/services"
	"hnex.com/internal/utils"
)

// Declaration

type UserHandler struct {
	service *services.UserService
}

func NewUserHandler(service *services.UserService) *UserHandler {
	return &UserHandler{
		service: service,
	}
}

// Code

func (h *UserHandler) GetUser(c *gin.Context) {
	id := c.Param("id")

	user, err := h.service.FindOneById(id)
	if err != nil {
		utils.ResponseError(c, err, http.StatusNotFound)
		return
	}

	utils.ResponseSuccess(c, user, nil)
}

// Profile

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

	if err := h.service.UpdateProfile(user.Sub, payload); err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, nil, nil)
}

func (h *UserHandler) UpdateProfileImage(c *gin.Context) {
	var payload dtos.UpdateProfileImageDTO
	if err := c.ShouldBind(&payload); err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	claims, err := utils.GetUserCtx(c)
	if err != nil {
		utils.ResponseError(c, err, http.StatusNotFound)
		return
	}

	if err := h.service.UpdateProfileImage(claims.Sub, payload.Type, payload.File); err != nil {
		utils.ResponseError(c, err, http.StatusInternalServerError)
		return
	}

	utils.ResponseSuccess(c, nil, nil)
}

func (h *UserHandler) GetProfile(c *gin.Context) {
	claims, err := utils.GetUserCtx(c)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	user, err := h.service.FindOneById(claims.Sub)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	utils.ResponseSuccess(c, user, nil)
}
