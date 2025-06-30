package repositories

import (
	"strings"

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

// Search
func (r *CourseRepository) FindAndCountByName(name string, limit, page int) (int64, []*models.Course, error) {
	var totalCount int64
	var courses []*models.Course

	if err := r.DB.Model(&models.Course{}).
		Where("LOWER(name) LIKE ?", "%"+strings.ToLower(name)+"%").
		Count(&totalCount).Error; err != nil {
		return 0, nil, err
	}

	offset := (page - 1) * limit
	if offset < 0 {
		offset = 0
	}

	if err := r.DB.
		Where("LOWER(name) LIKE ?", "%"+strings.ToLower(name)+"%").
		Limit(limit).
		Offset(offset).
		Find(&courses).Error; err != nil {
		return 0, nil, err
	}

	return totalCount, courses, nil
}
