package models

type Tag struct {
	Base

	Name string `json:"name" gorm:"uniqueIndex"`
}
