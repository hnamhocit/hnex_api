package services

import (
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
)

type CourseService struct {
	Repo *repositories.CourseRepository
}

func (s *CourseService) GetCoursesWithPagination(limit, page int) (int64, []*models.Course, error) {
	var courses []*models.Course
	count, err := s.Repo.FindMany(&courses, limit, page)
	if err != nil {
		return 0, nil, err
	}

	return count, courses, nil
}
