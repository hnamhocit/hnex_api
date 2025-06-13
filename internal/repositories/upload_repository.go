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
	return r.DB.Where("id = ?", id).Delete(&models.Upload{}).Error
}
