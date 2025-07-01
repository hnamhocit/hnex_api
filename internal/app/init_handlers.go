package app

import (
	"gorm.io/gorm"
	"hnex.com/internal/handlers"
	"hnex.com/internal/repositories"
	"hnex.com/internal/services"
)

type Handlers struct {
	AuthHandler    *handlers.AuthHandler
	UserHandler    *handlers.UserHandler
	UploadHandler  *handlers.UploadHandler
	SearchHandler  *handlers.SearchHandler
	BlogHandler    *handlers.BlogHandler
	CourseHandler  *handlers.CourseHandler
	ProductHandler *handlers.ProductHandler
}

func InitHandlers(db *gorm.DB) *Handlers {
	// Repository pointers
	userRepo := &repositories.UserRepository{DB: db}
	authRepo := &repositories.AuthRepository{DB: db}
	uploadRepo := &repositories.UploadRepository{DB: db}
	blogRepo := &repositories.BlogRepository{DB: db}
	productRepo := &repositories.ProductRepository{DB: db}
	courseRepo := &repositories.CourseRepository{DB: db}
	ipGeoInfoRepo := &repositories.IpGeoInfoRepository{DB: db}

	// Services
	uploadService := services.NewUploadService(uploadRepo)
	blogService := services.NewBlogService(blogRepo, uploadService)
	courseService := services.NewCourseService(courseRepo)
	productService := services.NewProductService(productRepo)
	searchService := services.NewSearchService(blogRepo, courseRepo)
	userService := services.NewUserService(userRepo, uploadService)
	ipGeoInfoService := services.NewIpGeoInfoService(ipGeoInfoRepo)
	authService := services.NewAuthService(authRepo)
	mailService := services.NewMailService(db)

	// Handlers
	authHandler := handlers.NewAuthHandler(authService, userService, ipGeoInfoService, mailService)
	uploadHandler := handlers.NewUploadHandler(uploadService)
	userHandler := handlers.NewUserHandler(userService)
	searchHandler := handlers.NewSearchHandler(searchService)
	blogHandler := handlers.NewBlogHandler(blogService)
	courseHandler := handlers.NewCourseHandler(courseService)
	productHandler := handlers.NewProductHandler(productService)

	return &Handlers{
		AuthHandler:    authHandler,
		UserHandler:    userHandler,
		UploadHandler:  uploadHandler,
		SearchHandler:  searchHandler,
		BlogHandler:    blogHandler,
		CourseHandler:  courseHandler,
		ProductHandler: productHandler,
	}
}
