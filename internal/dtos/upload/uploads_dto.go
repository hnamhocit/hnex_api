package upload

import "mime/multipart"

type UploadsDTO struct {
	Files          []*multipart.FileHeader `form:"files" binding:"required"`
	UploadableId   *string                 `form:"uploadable_id" binding:"omitempty"`
	UploadableType *string                 `form:"uploadable_type" binding:"omitempty"`
}
