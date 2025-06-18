package repositories

import (
	"gorm.io/gorm"
	"hnex.com/internal/models"
)

type CourseRepository struct {
	DB *gorm.DB
}

func (r *CourseRepository) FindMany(courses *[]*models.Course, limit, page int) (int64, error) {
	var totalCount int64

	err := r.DB.Model(&models.Course{}).Count(&totalCount).Error
	if err != nil {
		return 0, err
	}

	offset := (page - 1) * limit
	err = r.DB.Preload("Author").Limit(limit).Offset(offset).Find(courses).Error
	if err != nil {
		return 0, err
	}

	return totalCount, nil
}
