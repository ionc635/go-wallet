package router

import (
	"lecture/go-wallet/controller"
	"lecture/go-wallet/jwt"
	"strings"

	"github.com/gin-gonic/gin"
)

func GetRouter() *gin.Engine {
	router := gin.Default()
	// 헬스 체크
	router.GET("/health", controller.Health)
	// 최초 니모닉 생성
	router.POST("/mnemonics", controller.NewMnemonicAndWallet)
	// 패스워드 로그인
	router.POST("/signin/password", liteAuth(), controller.SigninFromPassword)
	// 니모닉 로그인
	router.POST("/signin/mnemonic", controller.SigninFromMnemonic)
	// 지갑 추가
	router.POST("/wallets", liteAuth(), controller.AddWallet)
	// 지갑 삭제
	router.DELETE("/wallets", liteAuth(), controller.RemoveWallet)
	// router.POST("/wallets", controller.NewWallet)
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
