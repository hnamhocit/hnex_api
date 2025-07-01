package repositories

import (
	"gorm.io/gorm"
	"hnex.com/internal/models"
)

type UploadRepository struct {
	DB *gorm.DB
}

func (r *UploadRepository) Create(upload *models.Upload) error {
	return r.DB.Create(upload).Error
}

func (r *UploadRepository) CreateMany(uploads []*models.Upload) error {
	return r.DB.Create(uploads).Error
}

func (r *UploadRepository) Delete(id string) error {
	return r.DB.Unscoped().Where("id = ?", id).Delete(&models.Upload{}).Error
}

func (r *UploadRepository) DeleteByPath(path string) error {
	return r.DB.Unscoped().Where("path = ?", path).Delete(&models.Upload{}).Error
}

func (r *UploadRepository) FindOneByUserId(id string) (*models.Upload, error) {
	var upload models.Upload

	result := r.DB.Preload("User").First(&upload, "user_id = ?", id)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, result.Error
	}

	return &upload, nil
}
