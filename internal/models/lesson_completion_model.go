package models

type LessonCompletion struct {
	Base

	UserID string `json:"user_id" gorm:"not null;index:idx_user_lesson_completion,unique"`
	User   User   `gorm:"foreignKey:UserID" json:"user"`

	LessonID string `json:"lesson_id" gorm:"not null;index:idx_user_lesson_completion,unique"`
	Lesson   Lesson `gorm:"foreignKey:LessonID" json:"lesson"`

	Score int `json:"score" gorm:"default:0"`
}
