package router

import (
	"lecture/go-wallet/controller"

	"github.com/gin-gonic/gin"
)

func GetRouter() *gin.Engine {
	router := gin.Default()
	router.GET("/health", controller.Health)
	return router
}
