package models

type Course struct {
	Base

	Name         string  `json:"name"`
	Description  string  `json:"description"`
	Price        int64   `json:"price" gorm:"default:0"`
	Slug         string  `json:"slug" gorm:"uniqueIndex"`
	ThumbnailURL *string `json:"thumbnail_url"`
	Views        int64   `json:"views" gorm:"column:views"`

	AuthorId string `json:"author_id"`
	Author   User   `json:"author" gorm:"foreignKey:AuthorId"`
}
