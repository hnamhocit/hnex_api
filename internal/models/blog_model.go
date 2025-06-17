package models

type Blog struct {
	Base

	Title        string  `json:"title"`
	Content      string  `json:"content"`
	Slug         string  `json:"slug" gorm:"uniqueIndex"`
	Views        int64   `json:"views" gorm:"default:0"`
	ThumbnailURL *string `json:"thumbnail_url"`

	Attachments []Upload  `json:"attachments" gorm:"polymorphic:Uploadable"`
	Likes       []Like    `json:"likes" gorm:"polymorphic:Likeable"`
	Comments    []Comment `json:"comments" gorm:"polymorphic:Commentable"`
	AuthorId    string    `json:"author_id"`
	Author      User      `gorm:"foreignKey:AuthorId" json:"author"`
}
