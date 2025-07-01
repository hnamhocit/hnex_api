package app

import (
	"fmt"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"hnex.com/internal/config"
	"hnex.com/internal/middlewares"
)

func Start(env *config.Env, db *gorm.DB, hostname string) {
	gin.SetMode(gin.ReleaseMode)

	app := gin.Default()

	app.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"*"},
	}))

	// Handlers
	handlers := InitHandlers(db)
	authHandler := handlers.AuthHandler
	userHandler := handlers.UserHandler
	uploadHandler := handlers.UploadHandler
	searchHandler := handlers.SearchHandler
	blogHandler := handlers.BlogHandler
	courseHandler := handlers.CourseHandler
	productHandler := handlers.ProductHandler

	api := app.Group("api")

	api.Static("/assets", "./assets")

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
			// auth.GET("google", authHandler.GoogleAuth)
			// auth.GET("facebook", authHandler.FacebookAuth)
		}

		users := api.Group("users")
		users.Use(middlewares.AccessTokenMiddleware)
		{
			users.PUT("profile", userHandler.UpdateProfile)
			users.PATCH("profile/image", userHandler.UpdateProfileImage)
			users.GET("profile", userHandler.GetProfile)
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
			search.GET("blogs", searchHandler.SearchBlogs)
			search.GET("courses", searchHandler.SearchCourses)
		}

		blogs := api.Group("blogs")
		{
			blogs.POST("", middlewares.AccessTokenMiddleware, blogHandler.CreateBlog)
			blogs.GET("", blogHandler.GetBlogs)
			blogs.GET(":slug", blogHandler.GetBlogBySlug)
		}

		courses := api.Group("courses")
		{
			courses.GET("", courseHandler.GetCourses)
		}

		products := api.Group("products")
		{
			products.GET("", productHandler.GetProducts)
		}
	}

	app.Run(fmt.Sprintf(":%d", env.PORT))
}
