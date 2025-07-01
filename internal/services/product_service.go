package services

import (
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
)

// Declaration

type ProductService struct {
	repo *repositories.ProductRepository
}

func NewProductService(repo *repositories.ProductRepository) *ProductService {
	return &ProductService{
		repo: repo,
	}
}

// Code

func (s *ProductService) GetProductsWithPagination(limit, page int) (int64, []*models.Product, error) {
	var products []*models.Product
	count, err := s.repo.FindMany(&products, limit, page)
	if err != nil {
		return 0, nil, err
	}

	return count, products, nil
}
