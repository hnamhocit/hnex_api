package handlers

import (
	"errors"
	"log"

	"github.com/gin-gonic/gin"
	"hnex.com/internal/services"
	"hnex.com/internal/utils"
)

type SearchHandler struct {
	Service *services.SearchService
}

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

	log.Printf("Search query: %s, Limit: %d, Page: %d", query, limit, page)

	count, blogs, err := h.Service.GetBlogsWithPagination(query, limit, page)
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

	count, courses, err := h.Service.GetCoursesWithPagination(query, limit, page)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, gin.H{
		"count": count,
		"items": courses,
	}, nil)
}
