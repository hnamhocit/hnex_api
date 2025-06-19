package api

import (
	"fmt"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"hnex.com/internal/config"
	"hnex.com/internal/handlers"
	"hnex.com/internal/middlewares"
	"hnex.com/internal/repositories"
)

func Start(env *config.Env, db *gorm.DB, hostname string) {
	// gin.SetMode(gin.ReleaseMode)

	app := gin.Default()

	app.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"*"},
	}))

	app.Static("/assets", "./assets")

	// Repositories
	userRepo := repositories.UserRepository{DB: db}
	authRepo := repositories.AuthRepository{DB: db}
	uploadRepo := repositories.UploadRepository{DB: db}
	searchRepo := repositories.SearchRepository{DB: db}
	blogRepo := repositories.BlogRepository{DB: db}
	productRepo := repositories.ProductRepository{DB: db}
	courseRepo := repositories.CourseRepository{DB: db}
	ipGeoInfoRepo := repositories.IpGeoInfoRepository{DB: db}

	// Handlers
	authHandler := handlers.AuthHandler{Repo: &authRepo, UserRepo: &userRepo, IpGeoInfoRepo: &ipGeoInfoRepo}
	uploadHandler := handlers.UploadHandler{Repo: &uploadRepo}
	userHandler := handlers.UserHandler{Repo: &userRepo}
	searchHandler := handlers.SearchHandler{Repo: &searchRepo}
	blogHandler := handlers.BlogHandler{Repo: &blogRepo}
	courseHandler := handlers.CourseHandler{Repo: &courseRepo}
	productHandler := handlers.ProductHandler{Repo: &productRepo}

	api := app.Group("api")
	{
		api.GET("health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "OK"})
		})

		auth := api.Group("auth")
		{
			auth.POST("register", authHandler.Register)
			auth.POST("login", authHandler.Login)
			auth.GET("logout", middlewares.AccessTokenMiddleware, authHandler.Logout)
			auth.POST("refresh", authHandler.RefreshToken)
			auth.GET("google", authHandler.GoogleAuth)
			auth.GET("facebook", authHandler.FacebookAuth)
		}

		users := api.Group("users")
		{
			users.GET("profile", middlewares.AccessTokenMiddleware, userHandler.GetProfile)
			users.GET(":id", userHandler.GetUser)
		}

		uploads := api.Group("uploads")
		uploads.Use(middlewares.AccessTokenMiddleware)
		{
			uploads.POST("file", uploadHandler.Upload)
			uploads.POST("files", uploadHandler.Uploads)
			uploads.DELETE(":id", uploadHandler.Delete)
		}

		search := api.Group("search")
		{
			search.GET(":query", searchHandler.Search)
		}

		blogs := api.Group("blogs")
		{
			blogs.PATCH(":id/thumbnail-url", middlewares.AccessTokenMiddleware, blogHandler.UpdateThumbnailURL)
			blogs.POST("", middlewares.AccessTokenMiddleware, blogHandler.Create)
			blogs.GET("", blogHandler.FindMany)
			blogs.GET(":slug", blogHandler.FindOne)
		}

		courses := api.Group("courses")
		{
			courses.GET("", courseHandler.FindMany)
		}

		products := api.Group("products")
		{
			products.GET("", productHandler.FindMany)
		}
	}

	app.Run(fmt.Sprintf(":%d", env.PORT))
}
