package models

type Ban struct {
	Base

	Reason      string `json:"reason"`
	ExpiresAt   int64  `json:"expiresAt"`
	IsPermanent bool   `json:"is_permanent" gorm:"default:false"`

	UserId string `json:"user_id" gorm:"uniqueIndex"`
	User   User   `json:"user" gorm:"foreignKey:UserId"`
}
