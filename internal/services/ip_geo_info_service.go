package services

import (
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
)

// Declaration

type IpGeoInfoService struct {
	repo *repositories.IpGeoInfoRepository
}

func NewIpGeoInfoService(repo *repositories.IpGeoInfoRepository) *IpGeoInfoService {
	return &IpGeoInfoService{
		repo: repo,
	}
}

// Code

func (s *IpGeoInfoService) CreateIpGeoInfo(ipGeoInfo *models.IpGeoInfo) error {
	return s.repo.Create(ipGeoInfo)
}
