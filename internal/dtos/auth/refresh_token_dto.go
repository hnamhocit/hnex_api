package auth

type RefreshTokenDTO struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}
