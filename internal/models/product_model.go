package models

type Product struct {
	Base

	Name          string  `json:"name"`
	Descrtiption  string  `json:"description"`
	GithubURL     string  `json:"github_url"`
	ProductionURL string  `json:"production_url"`
	ThumbnailURL  *string `json:"thumbnail_url"`

	AuthorId string `json:"author_id"`
	Author   User   `json:"author" gorm:"foreignKey:AuthorId"`
}
