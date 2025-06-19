package dtos

type IpGeoInfoPayload struct {
	IP            string `json:"ip"`
	ASN           string `json:"asn"`
	ASName        string `json:"as_name"`
	ASDomain      string `json:"as_domain"`
	CountryCode   string `json:"country_code"`
	Country       string `json:"country"`
	ContinentCode string `json:"continent_code"`
	Continent     string `json:"continent"`
}

type RegisterDto struct {
	Email       string           `json:"email" binding:"required,email"`
	Password    string           `json:"password" binding:"required"`
	DisplayName string           `json:"display_name" binding:"required"`
	IpGeoInfo   IpGeoInfoPayload `json:"ip_geo_info"`
}
