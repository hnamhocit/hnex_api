package app

import (
	"fmt"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"hnex.com/internal/routers"
)

func Start(db *gorm.DB, PORT int) {
	// gin.SetMode(gin.ReleaseMode)

	app := gin.Default()
	app.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"*"},
	}))
	app.Static("/assets", "./assets")

	appContainer := Init(db)

	routers.SetupRouter(
		app,
		appContainer.Handlers,
		appContainer.AccessTokenMiddleware,
		appContainer.BanMiddleware,
	)

	app.Run(fmt.Sprintf(":%d", PORT))
}
