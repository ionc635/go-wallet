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

func NewWallet(c *gin.Context) {
	var body model.CreateWalletRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	mnemonic := body.Mnemonic

	seed, _ := hdWallet.NewSeedFromMnemonic(mnemonic)
	wallet, _ := hdWallet.NewFromSeed(seed)
	path := hdWallet.MustParseDerivationPath("m/44'/60'/0'/0/0")

	account, _ := wallet.Derive(path, false)
	privateKey, _ := wallet.PrivateKeyHex(account)

	address := account.Address.Hex()

	var result model.NewWalletResponse
	result.PrivateKey = privateKey
	result.Address = address

	c.IndentedJSON(http.StatusOK, result)
}
