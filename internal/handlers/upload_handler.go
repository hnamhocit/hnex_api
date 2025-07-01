package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	dtos "hnex.com/internal/dtos/upload"
	"hnex.com/internal/services"
	"hnex.com/internal/utils"
)

// Declaration

type UploadHandler struct {
	service *services.UploadService
}

func NewUploadHandler(service *services.UploadService) *UploadHandler {
	return &UploadHandler{
		service: service,
	}
}

// Code

func (h *UploadHandler) Upload(c *gin.Context) {
	var payload dtos.UploadDTO
	if err := c.ShouldBind(&payload); err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	user, err := utils.GetUserCtx(c)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	upload, err := h.service.SaveAndCreateUpload(
		payload.File,
		user.Sub,
		payload.UploadableId,
		payload.UploadableType,
	)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, upload, nil)
}

func (h *UploadHandler) Uploads(c *gin.Context) {
	var payload dtos.UploadsDTO
	if err := c.ShouldBind(&payload); err != nil {
		utils.ResponseError(c, err)
		return
	}

	user, err := utils.GetUserCtx(c)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	uploads, err := h.service.SaveAndCreateUploads(
		payload.Files,
		user.Sub,
		payload.UploadableId,
		payload.UploadableType,
	)

	utils.ResponseSuccess(c, uploads, nil)
}

func (h *UploadHandler) Delete(c *gin.Context) {
	id := c.Param("id")

	err := h.service.DeleteById(id)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, true, nil)
}
