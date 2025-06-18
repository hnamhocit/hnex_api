package config

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
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
	), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, err
	}

	db.AutoMigrate(
		&models.User{},
		&models.Upload{},
		&models.Blog{},
		&models.Like{},
		&models.Comment{},
		&models.Lesson{},
		&models.LessonCompletion{},
		&models.CourseMember{},
		&models.Course{},
		&models.Product{},
		&models.LessonGroup{},
		&models.Tag{},
		&models.Taggable{},
	)

	return db, nil
}
