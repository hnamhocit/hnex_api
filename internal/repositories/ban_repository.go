package repositories

import (
	"errors"

	"gorm.io/gorm"
	"hnex.com/internal/models"
)

type BanRepository struct {
	DB *gorm.DB
}

func (r *BanRepository) FindOneByUserId(id string) (*models.Ban, error) {
	var ban models.Ban
	if err := r.DB.First(&ban, "user_id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}

		return nil, err
	}

	return &ban, nil
}

func (r *BanRepository) Create(ban *models.Ban) error {
	return r.DB.Create(ban).Error
}

func (r *BanRepository) DeleteById(id string) error {
	var ban models.Ban
	return r.DB.Unscoped().Delete(&ban, id).Error
}

func (r *BanRepository) DeleteByUserId(id string) error {
	return r.DB.Unscoped().Delete(&models.Ban{}, "user_id = ?", id).Error
}
