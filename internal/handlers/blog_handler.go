package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	dtos "hnex.com/internal/dtos/blog"
	"hnex.com/internal/services"
	"hnex.com/internal/utils"
)

// Declaration

type BlogHandler struct {
	service *services.BlogService
}

func NewBlogHandler(service *services.BlogService) *BlogHandler {
	return &BlogHandler{
		service: service,
	}
}

// Code

func (h *BlogHandler) CreateBlog(c *gin.Context) {
	var payload dtos.CreateBlogDTO
	if err := c.ShouldBind(&payload); err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	user, err := utils.GetUserCtx(c)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	newBlog, err := h.service.CreateBlogWithTransaction(
		payload.Title,
		payload.Content,
		user.Sub,
		payload.Thumbnail,
		payload.Attachments,
	)

	utils.ResponseSuccess(c, newBlog, nil, http.StatusCreated)
}

func (h *BlogHandler) GetBlogs(c *gin.Context) {
	limit, page, err := utils.GetPaginationCtx(c)
	if err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	count, blogs, err := h.service.GetBlogsWithPagination(limit, page)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, gin.H{
		"items": blogs,
		"count": count,
	}, nil)
}

func (h *BlogHandler) GetBlogBySlug(c *gin.Context) {
	slug := c.Param("slug")

	blog, err := h.service.GetBlogDetails(slug)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, blog, nil, http.StatusCreated)
}
