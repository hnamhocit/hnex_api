package dtos

import "mime/multipart"

type UpdateProfileImageDTO struct {
	File *multipart.FileHeader `form:"file" binding:"required"`
	Type string                `form:"type" binding:"required,oneof=photo background"`
}
