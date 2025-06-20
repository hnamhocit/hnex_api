package models

type Upload struct {
	Base

	Name string `json:"name"`
	Size int64  `json:"size"`
	Path string `json:"path" gorm:"uniqueIndex"`

	UploadableID   *string `json:"uploadable_id,omitempty" gorm:"index"`
	UploadableType *string `json:"uploadable_type,omitempty" gorm:"index"`

	UserId string `json:"user_id"`
	User   User   `json:"user" gorm:"foreignKey:UserId"`
}
