package services

import (
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
)

// Declaration

type CourseService struct {
	repo *repositories.CourseRepository
}

func NewCourseService(repo *repositories.CourseRepository) *CourseService {
	return &CourseService{
		repo: repo,
	}
}

// Code

func (s *CourseService) GetCoursesWithPagination(limit, page int) (int64, []*models.Course, error) {
	var courses []*models.Course
	count, err := s.repo.FindMany(&courses, limit, page)
	if err != nil {
		return 0, nil, err
	}

	return count, courses, nil
}
