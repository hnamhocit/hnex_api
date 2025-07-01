package services

import (
	"errors"
	"mime/multipart"

	"gorm.io/gorm"
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
	"hnex.com/internal/utils"
)

// Declaration

type BlogService struct {
	repo          *repositories.BlogRepository
	uploadService *UploadService
}

func NewBlogService(repo *repositories.BlogRepository, uploadService *UploadService) *BlogService {
	return &BlogService{
		repo:          repo,
		uploadService: uploadService,
	}
}

// Code

func (s *BlogService) GetBlogsWithPagination(limit, page int) (int64, []*models.Blog, error) {
	var blogs []*models.Blog
	count, err := s.repo.FindMany(&blogs, limit, page)
	if err != nil {
		return 0, nil, err
	}

	return count, blogs, nil
}

func (s *BlogService) CreateBlogWithTransaction(title, content, authorId string, thumbnail *multipart.FileHeader, attachments []*multipart.FileHeader) (*models.Blog, error) {

	newBlog := models.Blog{
		Title:    title,
		Content:  content,
		Slug:     utils.Slugify(title),
		AuthorId: authorId,
	}

	err := s.repo.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&newBlog).Error; err != nil {
			return err
		}

		uploadableID := newBlog.ID
		uploadableType := "Blogs"

		upload, err := s.uploadService.SaveAndCreateUpload(
			thumbnail,
			authorId,
			&uploadableID,
			&uploadableType,
		)
		if err != nil {
			return err
		}

		url := utils.GetDownloadURL(upload.Path)
		newBlog.ThumbnailURL = &url

		if err := tx.Save(&newBlog).Error; err != nil {
			return err
		}

		if len(attachments) > 0 {
			_, err := s.uploadService.SaveAndCreateUploads(
				attachments,
				authorId,
				&uploadableID,
				&uploadableType,
			)
			if err != nil {
				return err
			}
		}

		return nil
	})

	return &newBlog, err
}

func (s *BlogService) GetBlogDetails(slug string) (*models.Blog, error) {
	blog, err := s.repo.FindOneBySlug(slug)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New("blog not found")
		}

		return nil, err
	}

	return blog, nil
}
