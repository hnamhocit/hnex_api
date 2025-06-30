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
	"hnex.com/internal/services"
)

func Start(env *config.Env, db *gorm.DB, hostname string) {
	gin.SetMode(gin.ReleaseMode)

	app := gin.Default()

	app.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"*"},
	}))

	// Repositories
	userRepo := repositories.UserRepository{DB: db}
	authRepo := repositories.AuthRepository{DB: db}
	uploadRepo := repositories.UploadRepository{DB: db}
	blogRepo := repositories.BlogRepository{DB: db}
	productRepo := repositories.ProductRepository{DB: db}
	courseRepo := repositories.CourseRepository{DB: db}
	ipGeoInfoRepo := repositories.IpGeoInfoRepository{DB: db}

	// Services
	uploadService := services.UploadService{Repo: &uploadRepo}
	blogService := services.BlogService{Repo: &blogRepo, UploadService: &uploadService}
	courseService := services.CourseService{Repo: &courseRepo}
	productService := services.ProductService{Repo: &productRepo}
	searchService := services.SearchService{BlogRepo: &blogRepo, CourseRepo: &courseRepo}

	// Handlers
	authHandler := handlers.AuthHandler{Repo: &authRepo, UserRepo: &userRepo, IpGeoInfoRepo: &ipGeoInfoRepo}
	uploadHandler := handlers.UploadHandler{Repo: &uploadRepo, Service: &uploadService}
	userHandler := handlers.UserHandler{Repo: &userRepo}
	searchHandler := handlers.SearchHandler{Service: &searchService}
	blogHandler := handlers.BlogHandler{Service: &blogService}
	courseHandler := handlers.CourseHandler{Service: &courseService}
	productHandler := handlers.ProductHandler{Service: &productService}

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
			auth.GET("google", authHandler.GoogleAuth)
			auth.GET("facebook", authHandler.FacebookAuth)
		}

		users := api.Group("users")
		users.Use(middlewares.AccessTokenMiddleware)
		{
			users.PUT(":id", userHandler.UpdateProfile)
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
			courses.GET("", courseHandler.FindMany)
		}

		products := api.Group("products")
		{
			products.GET("", productHandler.FindMany)
		}
	}

	app.Run(fmt.Sprintf(":%d", env.PORT))
}
