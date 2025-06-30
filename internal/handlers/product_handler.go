package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"hnex.com/internal/services"
	"hnex.com/internal/utils"
)

type ProductHandler struct {
	Service *services.ProductService
}

func (h *ProductHandler) FindMany(c *gin.Context) {
	limit, page, err := utils.GetPaginationCtx(c)
	if err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	count, products, err := h.Service.GetProductsWithPagination(limit, page)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, gin.H{
		"items": products,
		"count": count,
	}, nil)
}
