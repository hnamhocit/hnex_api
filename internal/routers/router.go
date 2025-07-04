package routers

import (
	"github.com/gin-gonic/gin"
	"hnex.com/internal/handlers"
	"hnex.com/internal/utils"
)

func SetupRouter(g *gin.Engine, handlers *handlers.Handlers, accessTokenMiddleware gin.HandlerFunc, banMiddleware gin.HandlerFunc) {
	authHandler := handlers.AuthHandler
	userHandler := handlers.UserHandler
	banHandler := handlers.BanHandler
	blogHandler := handlers.BlogHandler
	courseHandler := handlers.CourseHandler
	productHandler := handlers.ProductHandler

	api := g.Group("api")

	api.GET("health", func(c *gin.Context) {
		utils.ResponseSuccess(c, nil, nil)
	})

	{
		auth := api.Group("auth")
		{
			auth.POST("register", authHandler.Register)
			auth.POST("login", authHandler.Login)
			auth.GET("logout", accessTokenMiddleware, authHandler.Logout)
			auth.POST("refresh", authHandler.RefreshToken)
			auth.POST("send-code", accessTokenMiddleware, authHandler.SendCode)
			auth.POST("verify-code", accessTokenMiddleware, authHandler.VerifyCode)
		}

		users := api.Group("users")
		users.Use(accessTokenMiddleware, banMiddleware)
		{
			users.PUT("profile", userHandler.UpdateProfile)
			users.PATCH("profile/image", userHandler.UpdateProfileImage)
			users.GET("profile", userHandler.GetProfile)
			users.GET(":id", userHandler.GetUser)
		}

		bans := api.Group("bans")
		bans.Use(accessTokenMiddleware)
		{
			bans.GET(":userId", banHandler.GetBan)
			bans.POST(":userId", banHandler.SetBan)
			bans.DELETE(":userId", banHandler.RemoveBan)
		}

		products := api.Group("products")
		{
			products.GET("", productHandler.GetProducts)
		}

		blogs := api.Group("blogs")
		{
			blogs.GET("", blogHandler.GetBlogs)
			blogs.GET(":id", blogHandler.GetBlogBySlug)
			blogs.POST("", blogHandler.CreateBlog)
		}

		courses := api.Group("courses")
		{
			courses.GET("", courseHandler.GetCourses)
		}
	}
}
