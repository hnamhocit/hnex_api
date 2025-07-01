package handlers

import (
	"errors"

	"github.com/gin-gonic/gin"
	"hnex.com/internal/services"
	"hnex.com/internal/utils"
)

// Declaration

type SearchHandler struct {
	service *services.SearchService
}

func NewSearchHandler(service *services.SearchService) *SearchHandler {
	return &SearchHandler{
		service: service,
	}
}

// Code

func (h *SearchHandler) SearchBlogs(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		utils.ResponseError(c, errors.New("Query parameter 'q' is required"))
		return
	}

	limit, page, err := utils.GetPaginationCtx(c)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	count, blogs, err := h.service.GetBlogsWithPagination(query, limit, page)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, gin.H{
		"count": count,
		"items": blogs,
	}, nil)
}

func (h *SearchHandler) SearchCourses(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		utils.ResponseError(c, errors.New("Query parameter 'q' is required"))
		return
	}

	limit, page, err := utils.GetPaginationCtx(c)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	count, courses, err := h.service.GetCoursesWithPagination(query, limit, page)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, gin.H{
		"count": count,
		"items": courses,
	}, nil)
}
