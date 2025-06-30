package config

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"hnex.com/internal/models"
)

func ConnectDB(env *Env) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(
		env.DB_URL,
	), &gorm.Config{})
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
		&models.IpGeoInfo{},
	)

	return db, nil
}
