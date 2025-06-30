package services

import (
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
)

type ProductService struct {
	Repo *repositories.ProductRepository
}

func (s *ProductService) GetProductsWithPagination(limit, page int) (int64, []*models.Product, error) {
	var products []*models.Product
	count, err := s.Repo.FindMany(&products, limit, page)
	if err != nil {
		return 0, nil, err
	}

	return count, products, nil
}
