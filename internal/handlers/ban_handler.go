package handlers

import (
	"github.com/gin-gonic/gin"
	"hnex.com/internal/dtos/ban"
	"hnex.com/internal/services"
	"hnex.com/internal/utils"
)

// Declaration

type BanHandler struct {
	service *services.BanService
}

func NewBanHandler(banService *services.BanService) *BanHandler {
	return &BanHandler{
		service: banService,
	}
}

// Code

func (h *BanHandler) GetBan(c *gin.Context) {
	userId := c.Param("userId")

	ban, err := h.service.Getban(c.Request.Context(), userId)
	if err != nil {

		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, ban, nil)
}

func (h *BanHandler) SetBan(c *gin.Context) {
	userId := c.Param("userId")
	var payload ban.SetBanDTO

	if err := c.ShouldBindJSON(&payload); err != nil {
		utils.ResponseError(c, err)
		return
	}

	if err := h.service.SetBan(c.Request.Context(), userId, payload.Reason, payload.Duration.ToDuration(), payload.IsPermanent); err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, nil, nil)
}

func (h *BanHandler) RemoveBan(c *gin.Context) {
	userId := c.Param("userId")

	if err := h.service.RemoveBan(c.Request.Context(), userId); err != nil {

		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, nil, nil)
}
