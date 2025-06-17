package handlers

import (
	"net/http"

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
	var blogs []*models.Blog
	err := h.Repo.FindMany(&blogs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"code": 1, "msg": "Success", "data": blogs})
}

func (h *BlogHandler) FindOne(c *gin.Context) {
	id := c.Param(":id")

	var blog *models.Blog
	err := h.Repo.FindOne(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"code": 1, "msg": "Success", "data": blog})
}
