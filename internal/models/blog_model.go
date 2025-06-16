package models

type Blog struct {
	Base

	Title        string `json:"title"`
	Content      string `json:"content"`
	Views        int64  `json:"views"`
	ThumbnailURL string `json:"thumbnail_url"`

	Attachments []Upload  `json:"attachments" gorm:"polymorphic:Uploadable"`
	Likes       []Like    `json:"likes" gorm:"polymorphic:Likeable"`
	Comments    []Comment `json:"comments" gorm:"polymorphic:Commentable"`
	AuthorId    string    `json:"author_id"`
	Author      User      `gorm:"foreignKey:AuthorId" json:"author"`
}
