package models

type Like struct {
	Base

	LikeableID   string `json:"likeable_id"`
	LikeableType string `json:"likeble_type"`
	UserId       string `json:"user_id"`
	User         User   `gorm:"foreignKey:UserId" json:"user"`
}
