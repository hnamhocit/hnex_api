package services

import (
	"fmt"
	"mime/multipart"

	dtos "hnex.com/internal/dtos/user"
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
	"hnex.com/internal/utils"
)

// Declaration

type UserService struct {
	repo          *repositories.UserRepository
	uploadService *UploadService
}

func NewUserService(repo *repositories.UserRepository, uploadService *UploadService) *UserService {
	return &UserService{
		repo:          repo,
		uploadService: uploadService,
	}
}

// Code

func (s *UserService) FindOneById(id string) (*models.User, error) {
	return s.repo.FindOneById(id)
}

func (s *UserService) FindOneByEmail(email string) (*models.User, error) {
	return s.repo.FindOneByEmail(email)
}

// Profile

func (s *UserService) UpdateProfile(id string, fields dtos.UpdateProfileDTO) error {
	if err := s.repo.UpdateFieldsById(id, fields); err != nil {
		return err
	}

	return nil
}

func (s *UserService) UpdateProfileImage(userId, t string, file *multipart.FileHeader) error {
	upload, err := s.uploadService.SaveAndCreateUpload(file, userId, nil, nil)
	if err != nil {
		return err
	}

	user, err := s.FindOneById(userId)
	if err != nil {
		return err
	}

	var (
		currentURL *string
		field      string
	)

	switch t {
	case "photo":
		currentURL = user.PhotoURL
		field = "photo_url"
	case "background":
		currentURL = user.BackgroundURL
		field = "background_url"
	default:
		return fmt.Errorf("invalid type: %s", t)
	}

	if currentURL != nil && *currentURL != "" {
		path := utils.ExtractDownloadURL(*currentURL)
		if err := s.uploadService.DeleteByPath(path); err != nil {
			return err
		}
	}

	return s.repo.UpdateFieldById(userId, field, utils.GetDownloadURL(upload.Path))
}
