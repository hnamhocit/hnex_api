package app

import (
	"gorm.io/gorm"
	"hnex.com/internal/handlers"
	"hnex.com/internal/middlewares"
	"hnex.com/internal/repositories"
	"hnex.com/internal/services"
)

func Init(db *gorm.DB) *AppContainer {
	// Repositories
	userRepo := &repositories.UserRepository{DB: db}
	authRepo := &repositories.AuthRepository{DB: db}
	uploadRepo := &repositories.UploadRepository{DB: db}
	blogRepo := &repositories.BlogRepository{DB: db}
	productRepo := &repositories.ProductRepository{DB: db}
	courseRepo := &repositories.CourseRepository{DB: db}
	ipGeoInfoRepo := &repositories.IpGeoInfoRepository{DB: db}
	banRepo := &repositories.BanRepository{DB: db}

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
	banService := services.NewBanService(banRepo)

	// Handlers
	handlers := &handlers.Handlers{
		AuthHandler:    handlers.NewAuthHandler(authService, userService, ipGeoInfoService, mailService, banService),
		UserHandler:    handlers.NewUserHandler(userService),
		UploadHandler:  handlers.NewUploadHandler(uploadService),
		SearchHandler:  handlers.NewSearchHandler(searchService),
		BlogHandler:    handlers.NewBlogHandler(blogService),
		CourseHandler:  handlers.NewCourseHandler(courseService),
		ProductHandler: handlers.NewProductHandler(productService, uploadService),
		BanHandler:     handlers.NewBanHandler(banService),
	}

	// Middlewares
	banMiddleware := middlewares.BanMiddleware(banService)

	return &AppContainer{

		// Repos
		UserRepo:      userRepo,
		AuthRepo:      authRepo,
		UploadRepo:    uploadRepo,
		BlogRepo:      blogRepo,
		ProductRepo:   productRepo,
		CourseRepo:    courseRepo,
		IpGeoInfoRepo: ipGeoInfoRepo,
		BanRepo:       banRepo,

		// Services
		UserService:      userService,
		AuthService:      authService,
		UploadService:    uploadService,
		BlogService:      blogService,
		ProductService:   productService,
		CourseService:    courseService,
		SearchService:    searchService,
		IpGeoInfoService: ipGeoInfoService,
		MailService:      mailService,
		BanService:       banService,

		Handlers:              handlers,
		AccessTokenMiddleware: middlewares.AccessTokenMiddleware,
		BanMiddleware:         banMiddleware,
	}
}
