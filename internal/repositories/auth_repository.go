package repositories

import (
	"gorm.io/gorm"
	"hnex.com/internal/models"
)

type AuthRepository struct {
	DB *gorm.DB
}

func (r *AuthRepository) CreateUser(user *models.User) error {
	return r.DB.Create(user).Error
}

func (r *AuthRepository) GetVerficationCode(id string) (*string, error) {
	var user models.User
	if err := r.DB.Select("verification_code").Where("id = ?", id).First(&user).Error; err != nil {
		return nil, err
	}

	return user.VerificationCode, nil
}

func (r *AuthRepository) GetRefreshToken(id string) (*string, error) {
	var user models.User
	if err := r.DB.Select("refresh_token").Where("id = ?", id).First(&user).Error; err != nil {
		return nil, err
	}

	return user.RefreshToken, nil
}

func (r *AuthRepository) WithTransaction(fn func(tx *gorm.DB) error) error {
	tx := r.DB.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

func (r *AuthRepository) UpdateFieldsById(id string, fields map[string]interface{}) error {
	return r.DB.Model(&models.User{}).Where("id = ?", id).Updates(fields).Error
}

func (r *AuthRepository) UpdateFieldById(id string, field string, value interface{}) error {
	return r.DB.Model(&models.User{}).Where("id = ?", id).Update(field, value).Error
}
