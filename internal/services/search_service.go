package services

import (
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
)

// Declaration

type SearchService struct {
	blogRepo   *repositories.BlogRepository
	courseRepo *repositories.CourseRepository
}

func NewSearchService(blogRepo *repositories.BlogRepository, courseRepo *repositories.CourseRepository) *SearchService {
	return &SearchService{
		blogRepo:   blogRepo,
		courseRepo: courseRepo,
	}
}

// Code

func (s *SearchService) GetBlogsWithPagination(query string, limit, page int) (int64, []*models.Blog, error) {
	count, blogs, err := s.blogRepo.FindAndCountByTitle(query, limit, page)
	if err != nil {
		return 0, nil, err
	}

	return count, blogs, nil
}

func (s *SearchService) GetCoursesWithPagination(query string, limit, page int) (int64, []*models.Course, error) {
	count, courses, err := s.courseRepo.FindAndCountByName(query, limit, page)
	if err != nil {
		return 0, nil, err
	}

	return count, courses, nil
}
