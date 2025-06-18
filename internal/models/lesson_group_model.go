package models

import "gorm.io/gorm"

type LessonGroup struct {
	Base

	Title       string `json:"title" gorm:"not null"`
	Description string `json:"description" gorm:"type:text"`
	Order       int    `json:"order"`

	CourseID string `json:"course_id" gorm:"not null;index"`
	Course   Course `gorm:"foreignKey:CourseID" json:"course"`

	Lessons []Lesson `gorm:"foreignKey:LessonGroupID" json:"lessons"`
}

func (lg *LessonGroup) BeforeCreate(tx *gorm.DB) (err error) {
	if lg.Order == 0 {
		var maxOrder int
		err = tx.Model(&LessonGroup{}).
			Where("course_id = ?", lg.CourseID).
			Select("COALESCE(MAX(\"order\"), 0)"). // Use COALESCE to handle no existing records
			Row().Scan(&maxOrder)

		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		lg.Order = maxOrder + 1
	}
	return nil
}
