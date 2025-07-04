package product

import "mime/multipart"

type CreateProductDTO struct {
	Name      string                `form:"name" binding:"required"`
	GithubURL string                `form:"github_url" binding:"required"`
	Thumbnail *multipart.FileHeader `form:"thumbnail" binding:"required"`
}
