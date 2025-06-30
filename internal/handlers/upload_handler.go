package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	dtos "hnex.com/internal/dtos/upload"
	"hnex.com/internal/repositories"
	"hnex.com/internal/services"
	"hnex.com/internal/utils"
)

type UploadHandler struct {
	Service *services.UploadService
	Repo    *repositories.UploadRepository
}

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

	upload, err := h.Service.SaveAndCreateUpload(
		payload.File,
		user.Sub,
		payload.UploadableId,
		payload.UploadableType,
	)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{"code": 1, "msg": "Success", "data": upload})
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

	uploads, err := h.Service.SaveAndCreateUploads(
		payload.Files,
		user.Sub,
		payload.UploadableId,
		payload.UploadableType,
	)

	utils.ResponseSuccess(c, uploads, nil)
}

func (h *UploadHandler) Delete(c *gin.Context) {
	id := c.Param("id")

	err := h.Repo.Delete(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	utils.ResponseSuccess(c, true, nil)
}
