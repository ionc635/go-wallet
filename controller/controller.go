package controller

import (
	"context"
	"fmt"
	"lecture/go-wallet/model"
	"lecture/go-wallet/rpc"
	"net/http"
	"regexp"

	conf "lecture/go-wallet/config"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
	hdWallet "github.com/miguelmota/go-ethereum-hdwallet"
)

var config = conf.GetConfig("config/config.toml")

var (
	PRIVATE_KEY = config.Wallet.PrivateKey
	PUBLIC_KEY  = config.Wallet.PublicKey
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

func GetBalance(c *gin.Context) {
	client := rpc.NewRpcClient()

	account := common.HexToAddress(PUBLIC_KEY)

	balance, err := client.BalanceAt(context.Background(), account, nil)

	if err != nil {
		fmt.Println(err)
		return
	}

	c.IndentedJSON(http.StatusOK, gin.H{
		"msg":     "OK",
		"balance": balance,
	})
}

func CheckWalletValid(c *gin.Context) {
	var body model.CheckValidRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	re := regexp.MustCompile("^0x[0-9a-fA-F]{40}$")

	if !re.MatchString(body.Address) {
		c.IndentedJSON(http.StatusOK, gin.H{
			"msg":   "OK",
			"valid": false,
		})
		return
	}

	c.IndentedJSON(http.StatusOK, gin.H{
		"msg":   "OK",
		"valid": true,
	})
	return
}
