package repositories

import (
	"gorm.io/gorm"
	"hnex.com/internal/models"
)

type ProductRepository struct {
	DB *gorm.DB
}

func (r *ProductRepository) FindMany(products *[]*models.Product, limit, page int) (int64, error) {
	var totalCount int64

	err := r.DB.Model(&models.Product{}).Count(&totalCount).Error
	if err != nil {
		return 0, err
	}

	offset := (page - 1) * limit
	err = r.DB.Preload("Author").Limit(limit).Offset(offset).Find(products).Error
	if err != nil {
		return 0, err
	}

	return totalCount, nil
}

func (r *ProductRepository) Create(product *models.Product) error {
	return r.DB.Create(product).Error
}
