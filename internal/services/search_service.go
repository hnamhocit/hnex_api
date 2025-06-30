package services

import (
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
)

type SearchService struct {
	BlogRepo   *repositories.BlogRepository
	CourseRepo *repositories.CourseRepository
}

func (s *SearchService) GetBlogsWithPagination(query string, limit, page int) (int64, []*models.Blog, error) {
	count, blogs, err := s.BlogRepo.FindAndCountByTitle(query, limit, page)
	if err != nil {
		return 0, nil, err
	}

	return count, blogs, nil
}

func (s *SearchService) GetCoursesWithPagination(query string, limit, page int) (int64, []*models.Course, error) {
	count, courses, err := s.CourseRepo.FindAndCountByName(query, limit, page)
	if err != nil {
		return 0, nil, err
	}

	return count, courses, nil
}
