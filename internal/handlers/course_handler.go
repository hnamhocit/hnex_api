package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"hnex.com/internal/services"
	"hnex.com/internal/utils"
)

type CourseHandler struct {
	Service *services.CourseService
}

func (h *CourseHandler) FindMany(c *gin.Context) {
	limit, page, err := utils.GetPaginationCtx(c)
	if err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	count, courses, err := h.Service.GetCoursesWithPagination(limit, page)

	utils.ResponseSuccess(c, gin.H{
		"items": courses,
		"count": count,
	}, nil)
}
