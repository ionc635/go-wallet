package router

import (
	"lecture/go-wallet/controller"
	"lecture/go-wallet/jwt"
	"strings"

	"github.com/gin-gonic/gin"
)

func GetRouter() *gin.Engine {
	r := gin.New()
	r.Use(CORS())

	// 헬스 체크
	r.GET("/health", controller.Health)
	// 최초 니모닉 생성
	r.POST("/mnemonics", controller.NewMnemonicAndWallet)
	// 패스워드 로그인
	r.POST("/signin/password", liteAuth(), controller.SigninFromPassword)
	// 니모닉 로그인
	r.POST("/signin/mnemonic", controller.SigninFromMnemonic)
	// 지갑 추가
	r.POST("/wallets", liteAuth(), controller.AddWallet)
	// 지갑 삭제
	r.DELETE("/wallets", liteAuth(), controller.RemoveWallet)
	// 지갑 전체 조회
	r.GET("/wallets", liteAuth(), controller.GetWallets)

	// router.POST("/wallets", controller.NewWallet)
	// router.GET("/balances", controller.GetBalance)
	// router.POST("/wallets/valid", controller.CheckWalletValid)
	// router.POST("transfer/eth", controller.TransferETH)
	// router.GET("transactions", controller.GetTransactions)
	// router.GET("transactions/status", controller.GetTransactionStatus)
	return r
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

func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, X-Forwarded-For, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
