package models

type Upload struct {
	BaseModel

	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Path   string `json:"path"`
	UserId string `json:"user_id"`
	User   User   `gorm:"foreignKey:UserId" json:"user"`
}
