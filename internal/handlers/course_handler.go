package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"hnex.com/internal/services"
	"hnex.com/internal/utils"
)

// Declaration

type CourseHandler struct {
	service *services.CourseService
}

func NewCourseHandler(service *services.CourseService) *CourseHandler {
	return &CourseHandler{
		service: service,
	}
}

// Code

func (h *CourseHandler) GetCourses(c *gin.Context) {
	limit, page, err := utils.GetPaginationCtx(c)
	if err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	count, courses, err := h.service.GetCoursesWithPagination(limit, page)

	utils.ResponseSuccess(c, gin.H{
		"items": courses,
		"count": count,
	}, nil)
}
