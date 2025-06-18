package models

import "time"

type CourseMember struct {
	Base

	UserID string `json:"user_id" gorm:"not null;index:idx_user_course_enrollment,unique"`
	User   User   `gorm:"foreignKey:UserID" json:"user"`

	CourseID string `json:"course_id" gorm:"not null;index:idx_user_course_enrollment,unique"`
	Course   Course `gorm:"foreignKey:CourseID" json:"course"`

	EnrollmentDate time.Time  `json:"enrollment_date"`
	CompletionDate *time.Time `json:"completion_date"`
	Status         string     `json:"status" gorm:"default:'enrolled'"`
}
