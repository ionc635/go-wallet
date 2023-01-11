package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	conf "lecture/go-wallet/config"
	"lecture/go-wallet/db"
	"lecture/go-wallet/model"
	"lecture/go-wallet/rpc"
	"lecture/go-wallet/scan"
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
	ADDRESS     = config.Wallet.Address
)

func Health(c *gin.Context) {
	c.JSON(200, gin.H{
		"msg": "health",
	})
}

func NewMnemonicAndWallet(c *gin.Context) {
	var body model.NewMnemonicRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	password := body.Password
	hash := sha256.New()
	hash.Write([]byte(password))

	encryptdPw := hex.EncodeToString(hash.Sum(nil))

	entropy, _ := hdWallet.NewEntropy(128)

	mnemonic, _ := hdWallet.NewMnemonicFromEntropy(entropy)
	hash.Write([]byte(encryptdPw + mnemonic))
	mark := hex.EncodeToString(hash.Sum(nil))

	wallet, _ := hdWallet.NewFromMnemonic(mnemonic)

	client := rpc.NewRpcClient()
	// 이더리움 coin_type / main_net - 60, test_net - 1 /
	var coinType int = 60
	if chainId, _ := client.NetworkID(context.Background()); chainId != big.NewInt(1) {
		coinType = 1
	}

	path := hdWallet.MustParseDerivationPath("m/44'/" + fmt.Sprintf("%v", coinType) + "'/0'/0/0")

	account, _ := wallet.Derive(path, true)

	address := account.Address.Hex()

	db := db.GetConnector()
	dbResult, err := db.Exec("INSERT INTO test_db.key (password, mnemonic, mark) VALUES (?, hex(aes_encrypt(?, ?)), ?)", encryptdPw, mnemonic, password, mark)
	if err != nil {
		log.Fatal(err)
	}

	insertId, _ := dbResult.LastInsertId()
	_, err = db.Exec("INSERT INTO test_db.address (address, keyId) VALUES (?, ?)", address, insertId)
	if err != nil {
		log.Fatal(err)
	}

	var result model.NewMnemonicAndWalletResponse
	result.Mnemonic = mnemonic
	result.Address = address
	result.Mark = mark

	c.IndentedJSON(http.StatusOK, gin.H{
		"msg":    "OK",
		"result": result,
	})
}

func NewWallet(c *gin.Context) {
	var body model.CreateWalletRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	mnemonic := body.Mnemonic

	wallet, _ := hdWallet.NewFromMnemonic(mnemonic)
	numOfWallets := len(wallet.Accounts())

	client := rpc.NewRpcClient()
	// 이더리움 coin_type / main_net - 60, test_net - 1 /
	var coinType int = 60
	if chainId, _ := client.NetworkID(context.Background()); chainId != big.NewInt(1) {
		coinType = 1
	}

	path := hdWallet.MustParseDerivationPath("m/44'/" + fmt.Sprintf("%v", coinType) + "'/0'/0/" + fmt.Sprintf("%v", numOfWallets))

	account, _ := wallet.Derive(path, true)
	privateKey, _ := wallet.PrivateKeyHex(account)

	address := account.Address.Hex()

	var result model.NewWalletResponse
	result.PrivateKey = privateKey
	result.Address = address

	c.IndentedJSON(http.StatusOK, gin.H{
		"msg":    "OK",
		"result": result,
	})
}

func GetBalance(c *gin.Context) {
	client := rpc.NewRpcClient()

	account := common.HexToAddress(ADDRESS)

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

func GetTransactions(c *gin.Context) {
	url := "/api?module=account&action=txlist&address=" + fmt.Sprintf("%v", ADDRESS) + "&startblock=0&endblock=99999999&page=0&offset=100&sort=desc&apikey="

	resp, err := scan.NewHttpRequest(url)

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var response model.GetTransactions
	if err = json.Unmarshal(data, &response); err != nil {
		log.Fatal(err)
	}

	c.IndentedJSON(http.StatusOK, gin.H{
		"msg":    "OK",
		"count":  len(response.Result),
		"result": response,
	})
}

func GetTransactionStatus(c *gin.Context) {
	var body model.GetTransactionStatusRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	client := rpc.NewRpcClient()
	if _, isPending, err := client.TransactionByHash(context.Background(), body.Hash); err != nil {
		log.Fatal(err)
	} else {
		c.IndentedJSON(http.StatusOK, gin.H{
			"msg":       "OK",
			"isPending": isPending,
		})
	}
}
