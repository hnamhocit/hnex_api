package auth

type VerifyCodeDTO struct {
	Code string `json:"code" binding:"required"`
}
