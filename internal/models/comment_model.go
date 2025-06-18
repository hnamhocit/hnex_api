package models

type Comment struct {
	Base

	Content string `json:"content"`

	CommentableID   string   `json:"commentable_id" gorm:"index"`
	CommentableType string   `json:"commentable_type" gorm:"index"`
	Attachments     []Upload `json:"attachments" gorm:"polymorphic:Uploadable"`
	Likes           []Like   `json:"likes" gorm:"polymorphic:Likeable"`
	UserId          string   `json:"user_id"`
	User            User     `gorm:"foreignKey:UserId" json:"user"`
}
