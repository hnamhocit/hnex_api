package models

type Comment struct {
	Base

	Content string `json:"content"`
	Views   int64  `json:"views"`

	CommentableID   string   `json:"commentable_id"`
	CommentableType string   `json:"commentable_type"`
	Attachments     []Upload `json:"attachments" gorm:"polymorphic:Uploadable"`
	Likes           []Like   `json:"likes" gorm:"polymorphic:Likeable"`
	UserId          string   `json:"user_id"`
	User            User     `gorm:"foreignKey:UserId" json:"user"`
}
