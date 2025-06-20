package handlers

import (
	"log"
	"net/http"
	"os"
	"strings"

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

	var uploadableId *string
	var uploadableType *string
	var field *string

	uType := c.PostForm("uploadable_type")
	if uType != "" {
		uploadableType = &uType
	} else {
		uploadableType = nil
	}

	uId := c.PostForm("uploadable_id")
	if uId != "" {
		uploadableId = &uId
	} else {
		uploadableId = nil
	}

	f := c.PostForm("field")
	if f != "" {
		field = &f
	} else {
		field = nil
	}

	if field != nil {
		go func() {
			prevUpload, err := h.Repo.FindOneByUserId(user.Sub)
			if err != nil {
				log.Println(err.Error())
			}

			isExist := prevUpload != nil && (prevUpload.User.BackgroundURL != nil ||
				prevUpload.User.PhotoURL != nil)

			if isExist {
				// Remove prev file in disk
				os.Remove("./" + prevUpload.Path)

				if *field == "photo" {
					isPhotoExist := false

					if prevUpload.User.PhotoURL != nil {
						isExist = strings.Contains(*prevUpload.User.PhotoURL, prevUpload.Path)
					}

					if isPhotoExist {
						if err := h.Repo.Delete(prevUpload.ID); err != nil {
							log.Println(err.Error())
						}
					}

				} else {
					isBackgroundExist := false

					if prevUpload.User.BackgroundURL != nil {
						isBackgroundExist = strings.Contains(*prevUpload.User.BackgroundURL, prevUpload.Path)
					}

					if isBackgroundExist {
						if err := h.Repo.Delete(prevUpload.ID); err != nil {
							log.Println(err.Error())
						}
					}
				}

			}
		}()
	}

	path := utils.GenUniquePath(file.Filename)
	c.SaveUploadedFile(file, "./"+path)

	upload := models.Upload{
		Name:           file.Filename,
		Size:           file.Size,
		Path:           path,
		UserId:         user.Sub,
		UploadableID:   uploadableId,
		UploadableType: uploadableType,
	}

	if err := h.Repo.Create(&upload); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"code": 1, "msg": "Success", "data": upload})
}

func (h *UploadHandler) Uploads(c *gin.Context) {

	user, err := utils.GetUserCtx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	form, _ := c.MultipartForm()
	files := form.File["files"]

	var uploadableId *string
	var uploadableType *string

	uType := c.PostForm("uploadable_type")
	if uType != "" {
		uploadableType = &uType
	} else {
		uploadableType = nil
	}

	uId := c.PostForm("uploadable_id")
	if uId != "" {
		uploadableId = &uId
	} else {
		uploadableId = nil
	}

	uploads := []*models.Upload{}

	for _, file := range files {
		path := utils.GenUniquePath(file.Filename)
		c.SaveUploadedFile(file, "./"+path)

		upload := &models.Upload{
			Name:           file.Filename,
			Size:           file.Size,
			Path:           path,
			UserId:         user.Sub,
			UploadableID:   uploadableId,
			UploadableType: uploadableType,
		}

		uploads = append(uploads, upload)
	}

	if err := h.Repo.CreateMany(uploads); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
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
