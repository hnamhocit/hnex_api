package auth

import ipgeoinfo "hnex.com/internal/dtos/ip_geo_info"

type RegisterDTO struct {
	Email       string                 `json:"email" binding:"required,email"`
	Password    string                 `json:"password" binding:"required"`
	DisplayName string                 `json:"display_name" binding:"required"`
	IpGeoInfo   ipgeoinfo.IpGeoInfoDTO `json:"ip_geo_info"`
}
