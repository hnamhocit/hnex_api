package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
)

type ProductHandler struct {
	Repo *repositories.ProductRepository
}

func (h *ProductHandler) FindMany(c *gin.Context) {
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

	var products []*models.Product
	count, err := h.Repo.FindMany(&products, limit, page)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"code": 1, "msg": "Success", "data": gin.H{
		"items": products,
		"count": count,
	}})
}
