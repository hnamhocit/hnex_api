package handlers

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"hnex.com/internal/dtos/user"
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
	var payload user.UpdateProfileDTO
	if err := c.ShouldBindJSON(&payload); err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	log.Println("UpdateProfile payload:", payload)
	if payload.PhoneNumber != nil && payload.CountryCode != nil {
		if *payload.PhoneNumber != "" && *payload.CountryCode != "" {
			formattedPhone, err := utils.E164Format(*payload.PhoneNumber, *payload.CountryCode)
			if err != nil {
				utils.ResponseError(c, err, http.StatusBadRequest)
				return
			}

			payload.PhoneNumber = &formattedPhone
		}
	}

	claims, err := utils.GetClaimsCtx(c)
	if err != nil {
		utils.ResponseError(c, err, http.StatusNotFound)
		return
	}

	if err := h.service.UpdateProfile(claims.Sub, payload); err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, nil, nil)
}

func (h *UserHandler) UpdateProfileImage(c *gin.Context) {
	var payload user.UpdateProfileImageDTO
	if err := c.ShouldBind(&payload); err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	claims, err := utils.GetClaimsCtx(c)
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
	claims, err := utils.GetClaimsCtx(c)
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
