package blog

import "mime/multipart"

type CreateBlogDTO struct {
	Thumbnail   *multipart.FileHeader   `form:"thumbnail" binding:"required"`
	Attachments []*multipart.FileHeader `form:"attachments" binding:"omitempty"`
	Title       string                  `form:"title" binding:"required"`
	Content     string                  `form:"content" binding:"required"`
}
