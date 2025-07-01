package services

import (
	"mime/multipart"
	"os"

	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
	"hnex.com/internal/utils"
)

// Declaration

type UploadService struct {
	repo *repositories.UploadRepository
}

func NewUploadService(repo *repositories.UploadRepository) *UploadService {
	return &UploadService{
		repo: repo,
	}
}

// Code

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

	if err := s.repo.Create(&upload); err != nil {
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
	if err := s.repo.CreateMany(uploads); err != nil {
		return nil, err
	}

	return uploads, nil
}

func (s *UploadService) DeleteById(id string) error {
	if err := s.repo.Delete(id); err != nil {
		return err
	}

	return nil
}

func (s *UploadService) DeleteByPath(path string) error {
	if err := s.repo.DeleteByPath(path); err != nil {
		return err
	}

	os.Remove("./" + path)

	return nil
}
