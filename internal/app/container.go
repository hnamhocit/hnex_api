package app

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"hnex.com/internal/config"
	"hnex.com/internal/handlers"
	"hnex.com/internal/repositories"
	"hnex.com/internal/services"
)

type AppContainer struct {
	DB  *gorm.DB
	Env *config.Env

	// Repositories
	UserRepo      *repositories.UserRepository
	AuthRepo      *repositories.AuthRepository
	UploadRepo    *repositories.UploadRepository
	BlogRepo      *repositories.BlogRepository
	ProductRepo   *repositories.ProductRepository
	CourseRepo    *repositories.CourseRepository
	IpGeoInfoRepo *repositories.IpGeoInfoRepository
	BanRepo       *repositories.BanRepository

	// Services
	UserService      *services.UserService
	AuthService      *services.AuthService
	UploadService    *services.UploadService
	BlogService      *services.BlogService
	ProductService   *services.ProductService
	CourseService    *services.CourseService
	SearchService    *services.SearchService
	IpGeoInfoService *services.IpGeoInfoService
	MailService      *services.MailService
	BanService       *services.BanService

	// Handlers
	Handlers *handlers.Handlers

	// Middleware
	AccessTokenMiddleware gin.HandlerFunc
	BanMiddleware         gin.HandlerFunc
}
