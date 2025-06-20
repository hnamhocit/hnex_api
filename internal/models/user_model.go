package models

import "time"

type Role string
type Gender string

const (
	ADMIN Role = "ADMIN"
	USER  Role = "USER"
)

const (
	MALE    Gender = "MALE"
	FEMALE  Gender = "FEMALE"
	OTHER   Gender = "OTHER"
	UNKNOWN Gender = "UNKNOWN"
)

type User struct {
	Base

	Email         string     `json:"email"`
	Password      string     `json:"password"`
	Provider      string     `json:"provider" gorm:"default:native"`
	Role          Role       `json:"role" gorm:"default:USER"`
	RefreshToken  *string    `json:"refresh_token"`
	DisplayName   string     `json:"display_name"`
	Gender        Gender     `json:"gender" gorm:"default:UNKNOWN"`
	Username      *string    `json:"username" gorm:"unique"`
	Bio           *string    `json:"bio"`
	PhotoURL      *string    `json:"photo_url"`
	BackgroundURL *string    `json:"background_url"`
	Location      *string    `json:"location"`
	PhoneNumber   *string    `json:"phone_number"`
	BirthDay      *time.Time `json:"birth_day"`

	CompletedLessons []LessonCompletion `gorm:"foreignKey:UserID" json:"completed_lessons"`
	IpGeoInfo        IpGeoInfo          `json:"ip_geo_info" gorm:"foreignKey:UserId"`
}
