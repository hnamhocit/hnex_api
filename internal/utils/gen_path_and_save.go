package utils

import (
	"mime/multipart"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func GenPathAndSave(file *multipart.FileHeader, c *gin.Context) (string, error) {
	ext := filepath.Ext(file.Filename)
	path := "assets/" + uuid.New().String() + ext
	if err := c.SaveUploadedFile(file, path); err != nil {
		return "", err
	}

	return path, nil
}
