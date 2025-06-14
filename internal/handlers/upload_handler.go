package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
	"hnex.com/internal/utils"
)

type UploadHandler struct {
	Repo *repositories.UploadRepository
}

func (h *UploadHandler) Upload(c *gin.Context) {
	user, err := utils.GetUserCtx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	path := utils.GenUniquePath(file.Filename)
	c.SaveUploadedFile(file, "./"+path)

	upload := models.Upload{Name: file.Filename, Size: file.Size, Path: path, UserId: user.Sub}
	uploadErr := h.Repo.Create(&upload)
	if uploadErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": uploadErr.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"code": 1, "msg": "Success", "data": true})
}

func (h *UploadHandler) Uploads(c *gin.Context) {

	user, err := utils.GetUserCtx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	form, _ := c.MultipartForm()
	files := form.File["files"]

	uploads := []*models.Upload{}

	for _, file := range files {
		path := utils.GenUniquePath(file.Filename)
		c.SaveUploadedFile(file, "./"+path)

		upload := &models.Upload{Name: file.Filename, Size: file.Size, Path: path, UserId: user.Sub}
		uploads = append(uploads, upload)
	}

	uploadErr := h.Repo.CreateMany(uploads)
	if uploadErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": uploadErr.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"code": 1, "msg": "Success", "data": true})
}

func (h *UploadHandler) Delete(c *gin.Context) {
	id := c.Param("id")

	err := h.Repo.Delete(id)
	if err != nil {

		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"code": 1, "msg": "Success", "data": true})
}
