package models

type Taggable struct {
	Base

	TagID string `json:"tag_id" gorm:"not null;index:idx_taggable_item,unique"`
	Tag   Tag    `gorm:"foreignKey:TagID" json:"tag"`

	TaggableID   string `json:"taggable_id" gorm:"not null;index:idx_taggable_item,unique"`
	TaggableType string `json:"taggable_type" gorm:"not null;index:idx_taggable_item,unique"`
}
