package services

import (
	"mime/multipart"

	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
	"hnex.com/internal/utils"
)

type UploadService struct {
	Repo *repositories.UploadRepository
}

func (s *UploadService) SaveAndCreateUpload(
	file *multipart.FileHeader,
	userId string,
	uploadableId *string,
	uploadableType *string,
) (*models.Upload, error) {

	path, err := utils.GenPathAndSave(file, nil)
	if err != nil {
		return nil, err
	}

	upload := models.Upload{
		Name:           file.Filename,
		Size:           file.Size,
		Path:           path,
		UserId:         userId,
		UploadableID:   uploadableId,
		UploadableType: uploadableType,
	}

	if err := s.Repo.Create(&upload); err != nil {
		return nil, err
	}

	return &upload, nil
}

func (s *UploadService) SaveAndCreateUploads(
	files []*multipart.FileHeader,
	userId string,
	uploadableId *string,
	uploadableType *string,
) ([]*models.Upload, error) {

	uploads := make([]*models.Upload, 0, len(files))

	for _, file := range files {
		path, err := utils.GenPathAndSave(file, nil)
		if err != nil {
			return nil, err
		}

		upload := &models.Upload{
			Name:           file.Filename,
			Size:           file.Size,
			Path:           path,
			UserId:         userId,
			UploadableID:   uploadableId,
			UploadableType: uploadableType,
		}

		uploads = append(uploads, upload)
	}
	if err := s.Repo.CreateMany(uploads); err != nil {
		return nil, err
	}

	return uploads, nil
}
