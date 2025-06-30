package dtos

import "mime/multipart"

type UploadDTO struct {
	File           *multipart.FileHeader `form:"file" binding:"required"`
	UploadableId   *string               `form:"uploadable_id" binding:"omitempty"`
	UploadableType *string               `form:"uploadable_type" binding:"omitempty"`
}
