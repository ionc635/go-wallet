package router

import (
	"lecture/go-wallet/controller"

	"github.com/gin-gonic/gin"
)

func GetRouter() *gin.Engine {
	router := gin.Default()
	router.GET("/health", controller.Health)
	router.POST("/mnemonics", controller.NewMnemonic)
	return router
}
