package config

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"hnex.com/internal/models"
)

func ConnectDB(env *Env) (*gorm.DB, error) {
	var dns string

	if env.NODE_ENV == "development" {
		dns = env.DEV_DB_URL
	} else {
		dns = env.PROD_DB_URL
	}

	db, err := gorm.Open(postgres.Open(
		dns,
	), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	db.AutoMigrate(&models.User{}, &models.Upload{}, &models.Blog{}, &models.Like{}, &models.Comment{})

	return db, nil
}
