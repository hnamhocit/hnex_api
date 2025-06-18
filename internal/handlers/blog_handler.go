package handlers

import (
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
	"hnex.com/internal/utils"
)

type BlogHandler struct {
	Repo *repositories.BlogRepository
}

type CreateBlogDTO struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

func (h *BlogHandler) Create(c *gin.Context) {
	var payload CreateBlogDTO
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	user, err := utils.GetUserCtx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	newBlog := models.Blog{
		Title:    payload.Title,
		Content:  payload.Content,
		Slug:     utils.Slugify(payload.Title),
		AuthorId: user.Sub,
	}
	if err := h.Repo.Create(&newBlog); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"code": 1, "msg": "Success", "data": newBlog})
}

type UpdateThumbnailDTO struct {
	ThumbnailURL string `json:"thumbnail_url"`
}

func (h *BlogHandler) UpdateThumbnailURL(c *gin.Context) {
	id := c.Param("id")

	var payload UpdateThumbnailDTO
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	if err := h.Repo.UpdateThumbnailURL(id, payload.ThumbnailURL); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"code": 1, "msg": "Success", "data": true})
}

func (h *BlogHandler) FindMany(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "10")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": "Invalid limit parameter"})
		return
	}

	pageStr := c.DefaultQuery("page", "1")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": "Invalid page parameter"})
		return
	}

	var blogs []*models.Blog
	count, err := h.Repo.FindMany(&blogs, limit, page)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	log.Println(count)

	c.JSON(http.StatusOK, gin.H{"code": 1, "msg": "Success", "data": gin.H{
		"items": blogs,
		"count": count,
	}})
}

func (h *BlogHandler) FindOne(c *gin.Context) {
	slug := c.Param("slug")

	blog, err := h.Repo.FindOneBySlug(slug)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"code": 1, "msg": "Success", "data": blog})
}
