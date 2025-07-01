package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"hnex.com/internal/services"
	"hnex.com/internal/utils"
)

// Declaration

type ProductHandler struct {
	service *services.ProductService
}

func NewProductHandler(service *services.ProductService) *ProductHandler {
	return &ProductHandler{
		service: service,
	}
}

// Code

func (h *ProductHandler) GetProducts(c *gin.Context) {
	limit, page, err := utils.GetPaginationCtx(c)
	if err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	count, products, err := h.service.GetProductsWithPagination(limit, page)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, gin.H{
		"items": products,
		"count": count,
	}, nil)
}
