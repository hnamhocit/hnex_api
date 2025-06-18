package models

type Upload struct {
	Base

	Name string `json:"name"`
	Size int64  `json:"size"`
	Path string `json:"path"`

	UploadableID   string `json:"uploadable_id" gorm:"index"`
	UploadableType string `json:"uploadable_type" gorm:"index"`
	UserId         string `json:"user_id"`
	User           User   `gorm:"foreignKey:UserId" json:"user"`
}
