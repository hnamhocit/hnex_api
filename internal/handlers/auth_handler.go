package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
	"hnex.com/internal/config"
	dtos "hnex.com/internal/dtos/auth"
	"hnex.com/internal/models"
	"hnex.com/internal/repositories"
	"hnex.com/internal/utils"
)

type AuthHandler struct {
	Repo          *repositories.AuthRepository
	UserRepo      *repositories.UserRepository
	IpGeoInfoRepo *repositories.IpGeoInfoRepository
}

// Providers Auth

func (h *AuthHandler) GoogleAuth(c *gin.Context) {
	var req dtos.GoogleAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	resp, err := http.Get("https://oauth2.googleapis.com/tokeninfo?id_token=" + req.IDToken)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		utils.ResponseError(c, fmt.Errorf("Google token validation failed: %s", string(bodyBytes)), resp.StatusCode)
		return
	}

	var googleInfo dtos.GoogleTokenInfo
	if err := json.NewDecoder(resp.Body).Decode(&googleInfo); err != nil {
		utils.ResponseError(c, fmt.Errorf("failed to parse Google token info"))
		return
	}

	if googleInfo.Aud != os.Getenv("GOOGLE_CLIENT_ID") {
		utils.ResponseError(c, fmt.Errorf("invalid audience (client ID mismatch)"), http.StatusUnauthorized)
		return
	}

	if time.Now().Unix() > googleInfo.Exp {
		utils.ResponseError(c, fmt.Errorf("Google token expired"), http.StatusUnauthorized)
		return
	}

	user, err := h.UserRepo.FindById(googleInfo.Sub)
	if err != nil && err != gorm.ErrRecordNotFound {
		utils.ResponseError(c, err)
		return
	}

	if user == nil {
		user = &models.User{
			Base: models.Base{
				ID: googleInfo.Sub,
			},
			Email:       googleInfo.Email,
			DisplayName: googleInfo.Name,
			Password:    "",
			PhotoURL:    &googleInfo.Picture,
			Provider:    "google",
		}

		if err := h.Repo.CreateUser(user); err != nil {
			utils.ResponseError(c, fmt.Errorf("failed to create user"))
			return
		}
	}

	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, user.Role, user.Provider)
	if err != nil {
		utils.ResponseError(c, fmt.Errorf("failed to generate JWT"))
		return
	}

	if err := h.Repo.UpdateRefreshToken(user.ID, &refreshToken); err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}, nil)
}

func (h *AuthHandler) FacebookAuth(c *gin.Context) {
	var req dtos.FacebookAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	debugURL := "https://graph.facebook.com/debug_token?input_token=" + req.AccessToken +
		"&access_token=" + os.Getenv("FACEBOOK_APP_ID") + "|" + os.Getenv("FACEBOOK_APP_SECRET")

	resp, err := http.Get(debugURL)
	if err != nil {
		utils.ResponseError(c, fmt.Errorf("failed to validate token with Facebook"))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		utils.ResponseError(c, fmt.Errorf("facebook token validation failed: %s", string(bodyBytes)), resp.StatusCode)
		return
	}

	var debugInfo dtos.FacebookDebugToken
	if err := json.NewDecoder(resp.Body).Decode(&debugInfo); err != nil {
		utils.ResponseError(c, fmt.Errorf("failed to parse Facebook debug info"))
		return
	}

	if !debugInfo.Data.IsValid {
		utils.ResponseError(c, fmt.Errorf("facebook token is invalid"), http.StatusUnauthorized)
		return
	}
	if debugInfo.Data.AppID != os.Getenv("FACEBOOK_APP_ID") {
		utils.ResponseError(c, fmt.Errorf("facebook token App ID mismatch"), http.StatusUnauthorized)
		return
	}

	userProfileURL := "https://graph.facebook.com/me?fields=id,name,email,picture.width(200).height(200)&access_token=" + req.AccessToken
	profileResp, err := http.Get(userProfileURL)
	if err != nil {
		utils.ResponseError(c, fmt.Errorf("failed to fetch Facebook user profile"))
		return
	}
	defer profileResp.Body.Close()

	if profileResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(profileResp.Body)
		utils.ResponseError(c, fmt.Errorf("facebook profile fetch failed: %s", string(bodyBytes)), profileResp.StatusCode)
		return
	}

	var facebookInfo dtos.FacebookUserInfo
	if err := json.NewDecoder(profileResp.Body).Decode(&facebookInfo); err != nil {
		utils.ResponseError(c, fmt.Errorf("failed to parse Facebook user info"))
		return
	}

	user, err := h.UserRepo.FindById(facebookInfo.ID)
	if err != nil && err != gorm.ErrRecordNotFound {
		utils.ResponseError(c, fmt.Errorf("failed to find user"))
		return
	}

	if user == nil {
		user = &models.User{
			Base: models.Base{
				ID: facebookInfo.ID,
			},
			Email:       facebookInfo.Email,
			DisplayName: facebookInfo.Name,
			Provider:    "facebook",
			PhotoURL:    &facebookInfo.Picture.Data.URL,
		}

		if err := h.Repo.CreateUser(user); err != nil {
			utils.ResponseError(c, fmt.Errorf("failed to create user"))
			return
		}
	}

	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, user.Role, user.Provider)
	if err != nil {
		utils.ResponseError(c, fmt.Errorf("failed to generate JWT"))
		return
	}

	if err := h.Repo.UpdateRefreshToken(user.ID, &refreshToken); err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}, nil)
}

// App Auth

func (h *AuthHandler) Register(c *gin.Context) {
	var data dtos.RegisterDto
	if err := c.ShouldBindJSON(&data); err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	existingUser, err := h.UserRepo.FindByEmail(data.Email)
	if err != nil && err != gorm.ErrRecordNotFound {
		utils.ResponseError(c, err)
		return
	}

	if existingUser != nil {
		utils.ResponseError(c, fmt.Errorf("user already exists"), http.StatusConflict)
		return
	}

	hashedPassword, err := utils.HashPassword(data.Password)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	user := models.User{
		Email:       data.Email,
		Password:    hashedPassword,
		DisplayName: data.DisplayName,
	}

	if err := h.Repo.CreateUser(&user); err != nil {
		utils.ResponseError(c, err)
		return
	}

	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, user.Role, "native")
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	if err := h.IpGeoInfoRepo.Create(&models.IpGeoInfo{
		IP:            data.IpGeoInfo.IP,
		ASN:           data.IpGeoInfo.ASN,
		ASName:        data.IpGeoInfo.ASName,
		ASDomain:      data.IpGeoInfo.ASDomain,
		CountryCode:   data.IpGeoInfo.CountryCode,
		Country:       data.IpGeoInfo.Country,
		ContinentCode: data.IpGeoInfo.ContinentCode,
		Continent:     data.IpGeoInfo.Continent,
		UserId:        user.ID,
	}); err != nil {
		utils.ResponseError(c, err)
		return
	}

	if err := h.Repo.UpdateRefreshToken(user.ID, &refreshToken); err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}, nil, http.StatusCreated)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var user dtos.LoginDto
	if err := c.ShouldBindJSON(&user); err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	existingUser, err := h.UserRepo.FindByEmail(user.Email)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			utils.ResponseError(c, fmt.Errorf("user not found"), http.StatusNotFound)
			return
		}

		utils.ResponseError(c, err)
		return
	}

	if existingUser == nil {
		utils.ResponseError(c, fmt.Errorf("email not found"), http.StatusBadRequest)
		return
	}

	match, err := utils.VerifyPassword(user.Password, existingUser.Password)
	if err != nil {
		utils.ResponseError(c, fmt.Errorf("password verification failed"), http.StatusBadRequest)
		return
	}

	if !match {
		utils.ResponseError(c, fmt.Errorf("password is incorrect"), http.StatusBadRequest)
		return
	}

	accessToken, refreshToken, err := utils.GenerateTokens(existingUser.ID, existingUser.Role, existingUser.Provider)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	if err := h.Repo.UpdateRefreshToken(existingUser.ID, &refreshToken); err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}, nil)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	claims, ok := c.Get("user")
	if !ok {
		utils.ResponseError(c, fmt.Errorf("unauthorized"), http.StatusUnauthorized)
		return
	}

	userID := claims.(*utils.JWTClaims).Sub

	if err := h.Repo.UpdateRefreshToken(userID, nil); err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, nil, nil)
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var refreshToken dtos.RefreshTokenDto
	if err := c.ShouldBindJSON(&refreshToken); err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	claims, ok := c.Get("user")
	if !ok {
		utils.ResponseError(c, fmt.Errorf("unauthorized"), http.StatusUnauthorized)
		return
	}

	user := claims.(*utils.JWTClaims)

	hashedRefreshToken, err := config.RedisClient.Get(context.Background(), fmt.Sprintf("user:%s:refresh_token", user.Sub)).Result()
	if err != nil {
		if err == redis.Nil {
			utils.ResponseError(c, fmt.Errorf("user has logged out"), http.StatusBadRequest)
			return
		}

		utils.ResponseError(c, err)
		return
	}

	match, err := utils.VerifyPassword(refreshToken.RefreshToken, hashedRefreshToken)
	if err != nil {
		utils.ResponseError(c, fmt.Errorf("password verification failed"), http.StatusBadRequest)
		return
	}

	if !match {
		utils.ResponseError(c, fmt.Errorf("refresh token is incorrect"), http.StatusBadRequest)
		return
	}

	accessToken, newRefreshToken, err := utils.GenerateTokens(user.Sub, user.Role, user.Provider)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	if err := h.Repo.UpdateRefreshToken(user.Sub, &newRefreshToken); err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, gin.H{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	}, nil)
}
