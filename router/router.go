package router

import (
	"lecture/go-wallet/controller"
	"lecture/go-wallet/jwt"
	"strings"

	"github.com/gin-gonic/gin"
)

func GetRouter() *gin.Engine {
	router := gin.Default()
	router.GET("/health", controller.Health)
	router.POST("/mnemonics", controller.NewMnemonicAndWallet)
	router.POST("/signin/password", liteAuth(), controller.SigninFromPassword)
	router.POST("/signin/mnemonic", controller.SigninFromMnemonic)
	router.POST("/wallets", controller.NewWallet)
	router.GET("/balances", controller.GetBalance)
	router.POST("/wallets/valid", controller.CheckWalletValid)
	router.POST("transfer/eth", controller.TransferETH)
	router.GET("transactions", controller.GetTransactions)
	router.GET("transactions/status", controller.GetTransactionStatus)
	return router
}

func liteAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c == nil {
			c.Abort()
			return
		}
		auth := c.GetHeader("Authorization")
		splited := strings.Split(auth, "Bearer ")
		mark := jwt.VerfyToken(splited[1])

		c.AddParam("mark", mark)
		c.Next()
	}
}
