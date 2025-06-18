package repositories

import (
	"gorm.io/gorm"
	"hnex.com/internal/models"
)

type BlogRepository struct {
	DB *gorm.DB
}

func (r *BlogRepository) FindMany(blogs *[]*models.Blog, limit, page int) (int64, error) {
	var totalCount int64

	err := r.DB.Model(&models.Blog{}).Count(&totalCount).Error
	if err != nil {
		return 0, err
	}

	offset := (page - 1) * limit
	err = r.DB.Preload("Author").Limit(limit).Offset(offset).Find(blogs).Error
	if err != nil {
		return 0, err
	}

	return totalCount, nil
}

func (r *BlogRepository) Create(blog *models.Blog) error {
	return r.DB.Create(blog).Error
}

func (r *BlogRepository) UpdateThumbnailURL(id, thumbnailURL string) error {
	return r.DB.Model(&models.Blog{}).Where("id = ?", id).Update("ThumbnailURL", thumbnailURL).Error
}

func (r *BlogRepository) FindOneBySlug(slug string) (*models.Blog, error) {
	var blog models.Blog

	err := r.DB.Preload("Comments").
		Preload("Attachments").
		Preload("Likes").
		Preload("Author").
		Where("slug = ?", slug).
		First(&blog).Error

	if err != nil {
		return nil, err
	}

	return &blog, nil
}
