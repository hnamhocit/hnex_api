package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
	"hnex.com/internal/config"
	dtos "hnex.com/internal/dtos/auth"
	"hnex.com/internal/models"
	"hnex.com/internal/services"
	"hnex.com/internal/utils"
)

type AuthHandler struct {
	service          *services.AuthService
	userService      *services.UserService
	ipGeoInfoService *services.IpGeoInfoService
	mailService      *services.MailService
}

func NewAuthHandler(service *services.AuthService, userService *services.UserService, ipGeoInfoService *services.IpGeoInfoService, mailService *services.MailService) *AuthHandler {
	return &AuthHandler{
		service:          service,
		userService:      userService,
		ipGeoInfoService: ipGeoInfoService,
		mailService:      mailService,
	}
}

// Providers Auth

// func (h *AuthHandler) GoogleAuth(c *gin.Context) {
// 	var req dtos.GoogleAuthRequest
// 	if err := c.ShouldBindJSON(&req); err != nil {
// 		utils.ResponseError(c, err, http.StatusBadRequest)
// 		return
// 	}
//
// 	resp, err := http.Get("https://oauth2.googleapis.com/tokeninfo?id_token=" + req.IDToken)
// 	if err != nil {
// 		utils.ResponseError(c, err)
// 		return
// 	}
// 	defer resp.Body.Close()
//
// 	if resp.StatusCode != http.StatusOK {
// 		bodyBytes, _ := io.ReadAll(resp.Body)
// 		utils.ResponseError(c, fmt.Errorf("Google token validation failed: %s", string(bodyBytes)), resp.StatusCode)
// 		return
// 	}
//
// 	var googleInfo dtos.GoogleTokenInfo
// 	if err := json.NewDecoder(resp.Body).Decode(&googleInfo); err != nil {
// 		utils.ResponseError(c, fmt.Errorf("failed to parse Google token info"))
// 		return
// 	}
//
// 	if googleInfo.Aud != os.Getenv("GOOGLE_CLIENT_ID") {
// 		utils.ResponseError(c, fmt.Errorf("invalid audience (client ID mismatch)"), http.StatusUnauthorized)
// 		return
// 	}
//
// 	if time.Now().Unix() > googleInfo.Exp {
// 		utils.ResponseError(c, fmt.Errorf("Google token expired"), http.StatusUnauthorized)
// 		return
// 	}
//
// 	user, err := h.userService.FindOneById(googleInfo.Sub)
// 	if err != nil && err != gorm.ErrRecordNotFound {
// 		utils.ResponseError(c, err)
// 		return
// 	}
//
// 	if user == nil {
// 		user = &models.User{
// 			Base: models.Base{
// 				ID: googleInfo.Sub,
// 			},
// 			Email:       googleInfo.Email,
// 			DisplayName: googleInfo.Name,
// 			Password:    "",
// 			PhotoURL:    &googleInfo.Picture,
// 			Provider:    "google",
// 		}
//
// 		if err := h.service.CreateUser(user); err != nil {
// 			utils.ResponseError(c, fmt.Errorf("failed to create user"))
// 			return
// 		}
// 	}
//
// 	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, user.Role, user.Provider)
// 	if err != nil {
// 		utils.ResponseError(c, fmt.Errorf("failed to generate JWT"))
// 		return
// 	}
//
// 	if err := h.service.UpdateRefreshToken(user.ID, &refreshToken); err != nil {
// 		utils.ResponseError(c, err)
// 		return
// 	}
//
// 	utils.ResponseSuccess(c, gin.H{
// 		"access_token":  accessToken,
// 		"refresh_token": refreshToken,
// 	}, nil)
// }
//
// func (h *AuthHandler) FacebookAuth(c *gin.Context) {
// 	var req dtos.FacebookAuthRequest
// 	if err := c.ShouldBindJSON(&req); err != nil {
// 		utils.ResponseError(c, err, http.StatusBadRequest)
// 		return
// 	}
//
// 	debugURL := "https://graph.facebook.com/debug_token?input_token=" + req.AccessToken +
// 		"&access_token=" + os.Getenv("FACEBOOK_APP_ID") + "|" + os.Getenv("FACEBOOK_APP_SECRET")
//
// 	resp, err := http.Get(debugURL)
// 	if err != nil {
// 		utils.ResponseError(c, fmt.Errorf("failed to validate token with Facebook"))
// 		return
// 	}
// 	defer resp.Body.Close()
//
// 	if resp.StatusCode != http.StatusOK {
// 		bodyBytes, _ := io.ReadAll(resp.Body)
// 		utils.ResponseError(c, fmt.Errorf("facebook token validation failed: %s", string(bodyBytes)), resp.StatusCode)
// 		return
// 	}
//
// 	var debugInfo dtos.FacebookDebugToken
// 	if err := json.NewDecoder(resp.Body).Decode(&debugInfo); err != nil {
// 		utils.ResponseError(c, fmt.Errorf("failed to parse Facebook debug info"))
// 		return
// 	}
//
// 	if !debugInfo.Data.IsValid {
// 		utils.ResponseError(c, fmt.Errorf("facebook token is invalid"), http.StatusUnauthorized)
// 		return
// 	}
// 	if debugInfo.Data.AppID != os.Getenv("FACEBOOK_APP_ID") {
// 		utils.ResponseError(c, fmt.Errorf("facebook token App ID mismatch"), http.StatusUnauthorized)
// 		return
// 	}
//
// 	userProfileURL := "https://graph.facebook.com/me?fields=id,name,email,picture.width(200).height(200)&access_token=" + req.AccessToken
// 	profileResp, err := http.Get(userProfileURL)
// 	if err != nil {
// 		utils.ResponseError(c, fmt.Errorf("failed to fetch Facebook user profile"))
// 		return
// 	}
// 	defer profileResp.Body.Close()
//
// 	if profileResp.StatusCode != http.StatusOK {
// 		bodyBytes, _ := io.ReadAll(profileResp.Body)
// 		utils.ResponseError(c, fmt.Errorf("facebook profile fetch failed: %s", string(bodyBytes)), profileResp.StatusCode)
// 		return
// 	}
//
// 	var facebookInfo dtos.FacebookUserInfo
// 	if err := json.NewDecoder(profileResp.Body).Decode(&facebookInfo); err != nil {
// 		utils.ResponseError(c, fmt.Errorf("failed to parse Facebook user info"))
// 		return
// 	}
//
// 	user, err := h.userService.FindOneById(facebookInfo.ID)
// 	if err != nil && err != gorm.ErrRecordNotFound {
// 		utils.ResponseError(c, fmt.Errorf("failed to find user"))
// 		return
// 	}
//
// 	if user == nil {
// 		user = &models.User{
// 			Base: models.Base{
// 				ID: facebookInfo.ID,
// 			},
// 			Email:       facebookInfo.Email,
// 			DisplayName: facebookInfo.Name,
// 			Provider:    "facebook",
// 			PhotoURL:    &facebookInfo.Picture.Data.URL,
// 		}
//
// 		if err := h.service.CreateUser(user); err != nil {
// 			utils.ResponseError(c, fmt.Errorf("failed to create user"))
// 			return
// 		}
// 	}
//
// 	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, user.Role, user.Provider)
// 	if err != nil {
// 		utils.ResponseError(c, fmt.Errorf("failed to generate JWT"))
// 		return
// 	}
//
// 	if err := h.service.UpdateRefreshToken(user.ID, &refreshToken); err != nil {
// 		utils.ResponseError(c, err)
// 		return
// 	}
//
// 	utils.ResponseSuccess(c, gin.H{
// 		"access_token":  accessToken,
// 		"refresh_token": refreshToken,
// 	}, nil)
// }

// App Auth

func (h *AuthHandler) Register(c *gin.Context) {
	var data dtos.RegisterDto
	if err := c.ShouldBindJSON(&data); err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	existingUser, err := h.userService.FindOneByEmail(data.Email)
	if err != nil && err != gorm.ErrRecordNotFound {
		utils.ResponseError(c, err)
		return
	}

	if existingUser != nil {
		utils.ResponseError(c, fmt.Errorf("email already exists"), http.StatusConflict)
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

	ipGeoInfo := models.IpGeoInfo{
		IP:            data.IpGeoInfo.IP,
		ASN:           data.IpGeoInfo.ASN,
		ASName:        data.IpGeoInfo.ASName,
		ASDomain:      data.IpGeoInfo.ASDomain,
		CountryCode:   data.IpGeoInfo.CountryCode,
		Country:       data.IpGeoInfo.Country,
		ContinentCode: data.IpGeoInfo.ContinentCode,
		Continent:     data.IpGeoInfo.Continent,
		UserId:        user.ID,
	}

	if err := h.service.Register(&user, &ipGeoInfo); err != nil {
		utils.ResponseError(c, err)
		return
	}

	accessToken, refreshToken, err := utils.GenerateTokens(
		&utils.TokenParams{
			Id:          user.ID,
			Role:        user.Role,
			Provider:    user.Provider,
			CountryCode: user.IpGeoInfo.CountryCode,
		})
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	if err := h.service.UpdateRefreshToken(user.ID, &refreshToken); err != nil {
		utils.ResponseError(c, err)
		return
	}

	verificationCode, err := h.mailService.SendVerificationEmail(user.Email, user.DisplayName)
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	if err := h.service.UpdateVerificationCode(user.ID, verificationCode); err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}, nil, http.StatusCreated)
}

const MaxLoginAttempt = 5
const LoginAttemptTTL = 5 * time.Minute

func (h *AuthHandler) Login(c *gin.Context) {

	var payload dtos.LoginDto
	if err := c.ShouldBindJSON(&payload); err != nil {
		utils.ResponseError(c, err, http.StatusBadRequest)
		return
	}

	user, err := h.userService.FindOneByEmail(payload.Email)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			utils.ResponseError(c, fmt.Errorf("user not found"), http.StatusNotFound)
			return
		}

		utils.ResponseError(c, err)
		return
	}

	attemptKey := fmt.Sprintf("users:%s:login_attempt", user.ID)
	attemptStr, _ := config.RedisClient.Get(context.Background(), attemptKey).Result()

	attempt := 0
	if attemptStr != "" {
		attempt, _ = strconv.Atoi(attemptStr)
	}

	if attempt >= MaxLoginAttempt {
		utils.ResponseError(c, fmt.Errorf("too many failed attempts, try again in 5 minutes"), http.StatusTooManyRequests)
		return
	}

	match, err := utils.VerifyPassword(payload.Password, user.Password)
	if err != nil {
		utils.ResponseError(c, fmt.Errorf("password verification failed"), http.StatusBadRequest)
		return
	}

	if !match {
		pipe := config.RedisClient.TxPipeline()

		pipe.Incr(context.Background(), attemptKey)

		pipe.Expire(context.Background(), attemptKey, LoginAttemptTTL)

		_, _ = pipe.Exec(context.Background())

		utils.ResponseError(c, fmt.Errorf("password is incorrect"), http.StatusBadRequest)
		return
	}

	config.RedisClient.Del(context.Background(), attemptKey)

	accessToken, refreshToken, err := utils.GenerateTokens(
		&utils.TokenParams{
			Id:          user.ID,
			Role:        user.Role,
			Provider:    user.Provider,
			CountryCode: user.IpGeoInfo.CountryCode,
		})
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	if err := h.service.UpdateRefreshToken(user.ID, &refreshToken); err != nil {
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

	if err := h.service.UpdateRefreshToken(userID, nil); err != nil {
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

	accessToken, newRefreshToken, err := utils.GenerateTokens(
		&utils.TokenParams{
			Id:          user.ID,
			Role:        user.Role,
			Provider:    user.Provider,
			CountryCode: user.CountryCode,
		})
	if err != nil {
		utils.ResponseError(c, err)
		return
	}

	if err := h.service.UpdateRefreshToken(user.Sub, &newRefreshToken); err != nil {
		utils.ResponseError(c, err)
		return
	}

	utils.ResponseSuccess(c, gin.H{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	}, nil)
}
