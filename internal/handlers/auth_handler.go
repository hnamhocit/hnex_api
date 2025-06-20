package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	resp, err := http.Get("https://oauth2.googleapis.com/tokeninfo?id_token=" + req.IDToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate token with Google"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		c.JSON(resp.StatusCode, gin.H{"error": "Google token validation failed", "details": string(bodyBytes)})
		return
	}

	var googleInfo dtos.GoogleTokenInfo
	if err := json.NewDecoder(resp.Body).Decode(&googleInfo); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse Google token info"})
		return
	}

	if googleInfo.Aud != os.Getenv("GOOGLE_CLIENT_ID") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid audience (client ID mismatch)"})
		return
	}

	if time.Now().Unix() > googleInfo.Exp {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Google token expired"})
		return
	}

	user, err := h.UserRepo.FindById(googleInfo.Sub)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find user"})
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

		err = h.Repo.CreateUser(user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": "Failed to create user"})
			return
		}
	}

	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, user.Role, user.Provider)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT"})
		return
	}

	err = h.Repo.UpdateRefreshToken(user.ID, &refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 1, "msg": "Success", "data": gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}})
}

func (h *AuthHandler) FacebookAuth(c *gin.Context) {
	var req dtos.FacebookAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	debugURL := "https://graph.facebook.com/debug_token?input_token=" + req.AccessToken +
		"&access_token=" + os.Getenv("FACEBOOK_APP_ID") + "|" + os.Getenv("FACEBOOK_APP_SECRET")

	resp, err := http.Get(debugURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate token with Facebook"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		c.JSON(resp.StatusCode, gin.H{"error": "Facebook token validation failed", "details": string(bodyBytes)})
		return
	}

	var debugInfo dtos.FacebookDebugToken
	if err := json.NewDecoder(resp.Body).Decode(&debugInfo); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse Facebook debug info"})
		return
	}

	if !debugInfo.Data.IsValid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Facebook token is invalid"})
		return
	}
	if debugInfo.Data.AppID != os.Getenv("FACEBOOK_APP_ID") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Facebook token App ID mismatch"})
		return
	}

	userProfileURL := "https://graph.facebook.com/me?fields=id,name,email,picture.width(200).height(200)&access_token=" + req.AccessToken
	profileResp, err := http.Get(userProfileURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch Facebook user profile"})
		return
	}
	defer profileResp.Body.Close()

	if profileResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(profileResp.Body)
		c.JSON(profileResp.StatusCode, gin.H{"error": "Facebook profile fetch failed", "details": string(bodyBytes)})
		return
	}

	var facebookInfo dtos.FacebookUserInfo
	if err := json.NewDecoder(profileResp.Body).Decode(&facebookInfo); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse Facebook user info"})
		return
	}

	user, err := h.UserRepo.FindById(facebookInfo.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find user"})
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

		err = h.Repo.CreateUser(user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}
	}

	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, user.Role, user.Provider)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT"})
		return
	}

	err = h.Repo.UpdateRefreshToken(user.ID, &refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 1, "msg": "Success", "data": gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}})
}

// App Auth

func (h *AuthHandler) Register(c *gin.Context) {
	var data dtos.RegisterDto
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	existingUser, err := h.UserRepo.FindByEmail(data.Email)
	if err != nil && err != gorm.ErrRecordNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	if existingUser != nil {
		c.JSON(http.StatusConflict, gin.H{"code": 0, "msg": "User already exists"})
		return
	}

	hashedPassword, err := utils.HashPassword(data.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	user := models.User{
		Email:       data.Email,
		Password:    hashedPassword,
		DisplayName: data.DisplayName,
	}

	err = h.Repo.CreateUser(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, user.Role, "native")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	log.Println(data)

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
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	if err := h.Repo.UpdateRefreshToken(user.ID, &refreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 1, "msg": "Success", "data": gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var user dtos.LoginDto
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	existingUser, err := h.UserRepo.FindByEmail(user.Email)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"code": 0, "msg": "User not found!"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	if existingUser == nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": "Email not found"})
		return
	}

	match, err := utils.VerifyPassword(user.Password, existingUser.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": "Password is incorrect"})
		return
	}

	if !match {
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": "Password is incorrect"})
		return
	}

	accessToken, refreshToken, err := utils.GenerateTokens(existingUser.ID, existingUser.Role, existingUser.Provider)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	err = h.Repo.UpdateRefreshToken(existingUser.ID, &refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 1, "msg": "Success", "data": gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	claims, ok := c.Get("user")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 0, "msg": "Unauthorized"})
		return
	}

	userID := claims.(*utils.JWTClaims).Sub

	err := h.Repo.UpdateRefreshToken(userID, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 1, "msg": "Success"})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var refreshToken dtos.RefreshTokenDto
	if err := c.ShouldBindJSON(&refreshToken); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	claims, ok := c.Get("user")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 0, "msg": "Unauthorized"})
		return
	}

	user := claims.(*utils.JWTClaims)

	hashedRefreshToken, err := config.RedisClient.Get(context.Background(), fmt.Sprintf("user:%s:refresh_token", user.Sub)).Result()
	if err != nil {
		if err == redis.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": "User has logged out"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	match, err := utils.VerifyPassword(refreshToken.RefreshToken, hashedRefreshToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	if !match {
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": "Refresh token is incorrect"})
		return
	}

	accessToken, newRefreshToken, err := utils.GenerateTokens(user.Sub, user.Role, user.Provider)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	err = h.Repo.UpdateRefreshToken(user.Sub, &newRefreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 1, "msg": "Success", "data": gin.H{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	}})
}
