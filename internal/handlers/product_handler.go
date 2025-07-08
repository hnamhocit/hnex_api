package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"hnex.com/internal/dtos/product"
	"hnex.com/internal/models"
	"hnex.com/internal/services"
	"hnex.com/internal/utils"
)

// Declaration

type ProductHandler struct {
	service       *services.ProductService
	uploadService *services.UploadService
}

func NewProductHandler(service *services.ProductService, uploadService *services.UploadService) *ProductHandler {
	return &ProductHandler{
		service:       service,
		uploadService: uploadService,
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

func (h *ProductHandler) CreateProduct(c *gin.Context) {
	var payload product.CreateProductDTO
	if err := c.ShouldBind(&payload); err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	claims, err := utils.GetClaimsCtx(c)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	product := models.Product{
		Name:          payload.Name,
		Descrtiption:  payload.Description,
		ProductionURL: payload.ProductionURL,
		GithubURL:     payload.GithubURL,
		AuthorId:      claims.Sub,
	}
	if err := h.service.Create(&product); err != nil {
		utils.ResponseError(c, err)
		return
	}

	uploadableType := "Products"
	upload, err := h.uploadService.SaveAndCreateUpload(payload.Thumbnail, claims.Sub, &product.ID, &uploadableType)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	if err := h.service.UpdateFieldById(product.ID, "thumbnail_url", utils.GetDownloadURL(upload.Path)); err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, nil, nil)
}
