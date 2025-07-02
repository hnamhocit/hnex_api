package app

import (
	"fmt"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"hnex.com/internal/config"
)

func Start(env *config.Env, db *gorm.DB, hostname string) {
	gin.SetMode(gin.ReleaseMode)

	app := gin.Default()
	app.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"*"},
	}))

	appContainer := InitApp(env, db)
	handlers := appContainer.Handlers
	middleware := appContainer.AccessTokenMiddleware

	api := app.Group("api")
	api.Static("/assets", "./assets")

	api.GET("health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "OK"})
	})

	auth := api.Group("auth")
	{
		auth.POST("register", handlers.AuthHandler.Register)
		auth.POST("login", handlers.AuthHandler.Login)
		auth.GET("logout", middleware, handlers.AuthHandler.Logout)
		auth.POST("refresh", handlers.AuthHandler.RefreshToken)
		auth.POST("send-code", middleware, handlers.AuthHandler.SendVerificationCode)
		auth.POST("verify-code", middleware, handlers.AuthHandler.VerifyCode)
	}

	users := api.Group("users")
	users.Use(middleware)
	{
		users.PUT("profile", handlers.UserHandler.UpdateProfile)
		users.PATCH("profile/image", handlers.UserHandler.UpdateProfileImage)
		users.GET("profile", handlers.UserHandler.GetProfile)
		users.GET(":id", handlers.UserHandler.GetUser)
	}

	app.Run(fmt.Sprintf(":%d", env.PORT))
}
