package repositories

import (
	"gorm.io/gorm"
	dtos "hnex.com/internal/dtos/user"
	"hnex.com/internal/models"
)

type UserRepository struct {
	DB *gorm.DB
}

func (r *UserRepository) UpdateFieldsById(id string, fields dtos.UpdateProfileDTO) error {
	return r.DB.Model(&models.User{}).Where("id = ?", id).Updates(fields).Error
}

func (r *UserRepository) UpdateFieldById(id string, field string, value interface{}) error {
	return r.DB.Model(&models.User{}).Where("id = ?", id).Update(field, value).Error
}

func (r *UserRepository) FindOneById(id string) (*models.User, error) {
	var user models.User
	if err := r.DB.Where("id = ?", id).Preload("IpGeoInfo").First(&user).Error; err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) FindOneByEmail(email string) (*models.User, error) {
	var user models.User
	if err := r.DB.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}

	return &user, nil
}
