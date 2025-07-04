package user

import (
	"hnex.com/internal/models"
)

type UpdateProfileDTO struct {
	DisplayName string        `json:"display_name,omitempty"`
	Gender      models.Gender `json:"gender,omitempty" gorm:"default:UNKNOWN"`
	Username    *string       `json:"username,omitempty" gorm:"unique"`
	Bio         *string       `json:"bio,omitempty"`
	Location    *string       `json:"location,omitempty"`
	PhoneNumber *string       `json:"phone_number,omitempty"`
	CountryCode *string       `json:"country_code,omitempty"`
	BirthDay    *string       `json:"birth_day,omitempty"`
}
