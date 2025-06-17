package repositories

import (
	"gorm.io/gorm"
	"hnex.com/internal/models"
)

type BlogRepository struct {
	DB *gorm.DB
}

func (r *BlogRepository) FindMany(blogs *[]*models.Blog) error {
	return r.DB.Find(blogs).Error
}

func (r *BlogRepository) Create(blog *models.Blog) error {
	return r.DB.Create(blog).Error
}

func (r *BlogRepository) UpdateThumbnailURL(id, thumbnailURL string) error {
	return r.DB.Model(&models.Blog{}).Where("id = ?", id).Update("ThumbnailURL", thumbnailURL).Error
}

func (r *BlogRepository) FindOne(id string) error {
	return r.DB.Find(&models.User{}, id).Error
}
