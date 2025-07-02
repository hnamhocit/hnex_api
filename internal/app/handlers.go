package app

import (
	"hnex.com/internal/handlers"
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
