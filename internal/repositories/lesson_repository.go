package repositories

import (
	"gorm.io/gorm"
)

type LessonRepository struct {
	DB *gorm.DB

	Name string `json:"name"`
}
