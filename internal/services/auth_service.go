package services

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
	"hnex.com/internal/config"
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
	"hnex.com/internal/utils"
)

// Declaration

type AuthService struct {
	repo *repositories.AuthRepository
}

func NewAuthService(repo *repositories.AuthRepository) *AuthService {
	return &AuthService{
		repo: repo,
	}
}

// Code

func (s *AuthService) CreateUser(user *models.User) error {
	if err := s.repo.CreateUser(user); err != nil {
		return err
	}

	return nil
}

func (s *AuthService) UpdateRefreshToken(id string, refreshToken *string) error {
	var hashedRefreshToken *string

	if refreshToken == nil {
		config.RedisClient.Del(context.Background(), fmt.Sprintf("user:%s:refresh_token", id))

		hashedRefreshToken = nil
	} else {
		hash, err := utils.HashPassword(*refreshToken)
		if err != nil {
			return err
		}

		config.RedisClient.Set(context.Background(), fmt.Sprintf("user:%s:refresh_token", id), hash, 14*24*time.Hour)

		hashedRefreshToken = &hash
	}

	if err := s.repo.UpdateFieldById(id, "refresh_token", hashedRefreshToken); err != nil {
		return err
	}

	return nil
}

func (s *AuthService) Register(user *models.User, ipGeo *models.IpGeoInfo) error {
	return s.repo.WithTransaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return err
		}

		ipGeo.UserId = user.ID

		if err := tx.Create(ipGeo).Error; err != nil {
			return err
		}

		return nil
	})
}

func (s *AuthService) UpdateEmailVerified(id string) error {
	return s.repo.UpdateFieldsById(id, map[string]interface{}{"verification_code": nil, "is_email_verified": true})
}

func (s *AuthService) UpdateVerificationCode(id string, verificationCode string) error {
	return s.repo.UpdateFieldById(id, "verification_code", verificationCode)
}
