package controller

import (
	"crypto/ecdsa"
	"fmt"
	"lecture/go-wallet/model"
	"lecture/go-wallet/rpc"
	"log"
	"net/http"

	conf "lecture/go-wallet/config"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	hdWallet "github.com/miguelmota/go-ethereum-hdwallet"
)

var config = conf.GetConfig("config/config.toml")

var (
	PRIVATE_KEY = config.Wallet.PrivateKey
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

// TODO: json: cannot unmarshal string into Go value of type controller.Balance 에러 해결
func GetBalance(c *gin.Context) {
	client := rpc.NewRpcClient()

	privateKey, err := crypto.HexToECDSA(PRIVATE_KEY)
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privateKey.Public()

	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	var balance Balance

	err = client.Call(&balance, "eth_getBalance", fromAddress.String(), "latest")

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Latest block: %v\n", balance.result)
}

// type Balance struct {
// 	Jsonrpc string      `json:"jsonrpc"`
// 	Id      json.Number `json:"id"`
// 	Result  string      `json:"result"`
// }

type Balance struct {
	jsonrpc string
	id      int
	result  string
}
