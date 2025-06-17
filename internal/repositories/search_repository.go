package repositories

import "gorm.io/gorm"

type SearchRepository struct {
	DB *gorm.DB
}
