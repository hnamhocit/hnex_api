package models

type Like struct {
	Base

	LikeableID   string `json:"likeable_id" gorm:"index"`
	LikeableType string `json:"likeable_type" gorm:"index"`
	UserId       string `json:"user_id"`
	User         User   `gorm:"foreignKey:UserId" json:"user"`
}
