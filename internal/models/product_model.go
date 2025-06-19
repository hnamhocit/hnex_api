package models

type Product struct {
	Base

	Name         string  `json:"name"`
	GithubURL    string  `json:"github_url"`
	ThumbnailURL *string `json:"thumbnail_url"`

	AuthorId string `json:"author_id"`
	Author   User   `json:"author" gorm:"foreignKey:AuthorId"`
}
