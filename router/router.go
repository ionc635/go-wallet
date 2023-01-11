package router

import (
	"lecture/go-wallet/controller"

	"github.com/gin-gonic/gin"
)

func GetRouter() *gin.Engine {
	router := gin.Default()
	router.GET("/health", controller.Health)
	router.POST("/mnemonics", controller.NewMnemonicAndWallet)
	router.POST("/signin/password", controller.SigninFromPassword)
	router.POST("/signin/mnemonic", controller.SigninFromMnemonic)
	router.POST("/wallets", controller.NewWallet)
	router.GET("/balances", controller.GetBalance)
	router.POST("/wallets/valid", controller.CheckWalletValid)
	router.POST("transfer/eth", controller.TransferETH)
	router.GET("transactions", controller.GetTransactions)
	router.GET("transactions/status", controller.GetTransactionStatus)
	return router
}
