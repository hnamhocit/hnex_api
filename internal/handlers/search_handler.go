package handlers

import (
	"github.com/gin-gonic/gin"
	"hnex.com/internal/repositories"
)

type SearchHandler struct {
	Repo *repositories.SearchRepository
}

func (h *SearchHandler) Search(c *gin.Context) {

}
