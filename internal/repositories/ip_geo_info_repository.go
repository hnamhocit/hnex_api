package repositories

import (
	"gorm.io/gorm"
	"hnex.com/internal/models"
)

type IpGeoInfoRepository struct {
	DB *gorm.DB
}

func (r *IpGeoInfoRepository) Create(ipGeoInfo *models.IpGeoInfo) error {
	return r.DB.Create(ipGeoInfo).Error
}
