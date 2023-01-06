package controller

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	conf "lecture/go-wallet/config"
	"lecture/go-wallet/model"
	"lecture/go-wallet/rpc"
	"log"
	"math/big"
	"net/http"
	"regexp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
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

func TransferETH(c *gin.Context) {
	var body model.TransferETHRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	privateKey, err := crypto.HexToECDSA(PRIVATE_KEY)
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	client := rpc.NewRpcClient()
	nonce, err := client.PendingNonceAt(context.Background(), address)
	if err != nil {
		log.Fatal(err)
	}

	value := big.NewInt(body.Amount)
	gasLimit := uint64(21000)
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	balance, err := client.BalanceAt(context.Background(), address, nil)
	if err != nil {
		log.Fatal(err)
	}

	gasFee := new(big.Int)
	totalAmount := new(big.Int)

	gasFee.Mul(gasPrice, big.NewInt(int64(gasLimit)))
	totalAmount.Add(value, gasFee)

	if balance.Cmp(totalAmount) != 1 {
		c.IndentedJSON(http.StatusBadRequest, gin.H{
			"msg": "insufficient funds for gas * price + value",
		})
		return
	}

	tx := types.NewTransaction(nonce, body.ToAddress, value, gasLimit, gasPrice, nil)

	chainId, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainId), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}

	c.IndentedJSON(http.StatusOK, gin.H{
		"msg": "OK",
		"tx":  signedTx.Hash().Hex(),
	})
}
