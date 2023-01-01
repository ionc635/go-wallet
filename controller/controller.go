package controller

import (
	"lecture/go-wallet/model"
	"net/http"

	"github.com/gin-gonic/gin"
	hdWallet "github.com/miguelmota/go-ethereum-hdwallet"
)

func Health(c *gin.Context) {
	c.JSON(200, gin.H{
		"msg": "health",
	})
}

func NewMnemonic(c *gin.Context) {
	entropy, _ := hdWallet.NewEntropy(256)
	mnemonic, _ := hdWallet.NewMnemonicFromEntropy(entropy)

	var result model.NewMnemonicResponse
	result.Mnemonic = mnemonic

	c.IndentedJSON(http.StatusOK, result)
}
