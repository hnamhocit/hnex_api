package models

import "gorm.io/gorm"

type Lesson struct {
	Base

	Title    string `json:"title" gorm:"not null"`
	Content  string `json:"content" gorm:"type:text"`
	VideoURL string `json:"video_url"`
	Order    int    `json:"order"`
	Views    int64  `json:"views" gorm:"default:0"`

	LessonGroupID string      `json:"lesson_group_id" gorm:"not null;index"`
	LessonGroup   LessonGroup `gorm:"foreignKey:LessonGroupID" json:"lesson_group"`

	CompletedByUsers []LessonCompletion `gorm:"foreignKey:LessonID" json:"completed_by_users"`
	Likes            []Like             `gorm:"polymorphic:Likeable;" json:"likes"`
	Attachments      []Upload           `gorm:"polymorphic:Uploadable" json:"attachments"`
}

func (l *Lesson) BeforeCreate(tx *gorm.DB) (err error) {
	if l.Order == 0 {
		var maxOrder int

		err = tx.Model(&Lesson{}).
			Where("lesson_group_id = ?", l.LessonGroupID).
			Select("COALESCE(MAX(\"order\"), 0)"). // Use COALESCE to handle no existing records
			Row().Scan(&maxOrder)
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}

		l.Order = maxOrder + 1
	}
	return nil
}
