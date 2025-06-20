package dtos

import (
	"time"

	"hnex.com/internal/models"
)

type UpdateProfileDTO struct {
	DisplayName   string        `json:"display_name,omitempty"`
	Gender        models.Gender `json:"gender,omitempty" gorm:"default:UNKNOWN"`
	Username      *string       `json:"username,omitempty" gorm:"unique"`
	Bio           *string       `json:"bio,omitempty"`
	PhotoURL      *string       `json:"photo_url,omitempty"`
	BackgroundURL *string       `json:"background_url,omitempty"`
	Location      *string       `json:"location,omitempty"`
	PhoneNumber   *string       `json:"phone_number,omitempty"`
	BirthDay      *time.Time    `json:"birth_day,omitempty"`
}
