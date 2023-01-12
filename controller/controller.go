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
	"lecture/go-wallet/jwt"
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

	// 패스워드 암호화
	password := body.Password
	hash := sha256.New()
	hash.Write([]byte(password))
	encryptdPw := hex.EncodeToString(hash.Sum(nil))

	// seed 생성
	entropy, _ := hdWallet.NewEntropy(128)

	// 니모닉 생성
	mnemonic, _ := hdWallet.NewMnemonicFromEntropy(entropy)

	// 고유 ID 생성
	hash.Write([]byte(encryptdPw + mnemonic))
	mark := hex.EncodeToString(hash.Sum(nil))

	// 지갑 생성
	wallet, _ := hdWallet.NewFromMnemonic(mnemonic)

	// coinType 확인
	client := rpc.NewRpcClient()
	// 이더리움 coin_type / main_net - 60, test_net - 1 /
	var coinType int = 60
	if chainId, _ := client.NetworkID(context.Background()); chainId != big.NewInt(1) {
		coinType = 1
	}

	// BIP44
	path := hdWallet.MustParseDerivationPath("m/44'/" + fmt.Sprintf("%v", coinType) + "'/0'/0/0")
	account, _ := wallet.Derive(path, true)

	// privateKey, address 생성
	privateKey, _ := wallet.PrivateKeyHex(account)
	address := account.Address.Hex()

	// INSERT
	db := db.GetConnector()
	dbResult, err := db.Exec("INSERT INTO test_db.key (password, mnemonic, mark) VALUES (?, hex(aes_encrypt(?, ?)), ?)", encryptdPw, mnemonic, mark, mark)
	if err != nil {
		log.Fatal(err)
	}

	insertId, _ := dbResult.LastInsertId()
	_, err = db.Exec("INSERT INTO test_db.address (address, privateKey, keyId, level, type) VALUES (?, hex(aes_encrypt(?, ?)), ?, ?, ?)", address, privateKey, mark, insertId, 0, coinType)
	if err != nil {
		log.Fatal(err)
	}

	// 토큰 생성
	token := jwt.CreateToken(mark)
	fmt.Println(mark)

	var result model.NewMnemonicAndWalletResponse
	result.Mnemonic = mnemonic
	result.Address = address
	result.Token = token

	c.IndentedJSON(http.StatusOK, gin.H{
		"msg":    "OK",
		"result": result,
	})
}

func SigninFromPassword(c *gin.Context) {
	var body model.SigninFromPasswordRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	mark := c.Param("mark")

	// 비밀번호 암호화
	password := body.Password
	hash := sha256.New()
	hash.Write([]byte(password))
	encryptdPw := hex.EncodeToString(hash.Sum(nil))

	// 비밀번호와 mark가 일치하는지 확인
	db := db.GetConnector()
	var id int
	err := db.QueryRow("SELECT (id) FROM test_db.key WHERE password = ? AND mark = ?", encryptdPw, mark).Scan(&id)

	if err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{
			"msg": "password is not vaild",
		})
		return
	}

	// Address 조회
	var data string
	var address []string
	rows, err := db.Query("SELECT address FROM test_db.address WHERE keyId = ?", id)

	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()

	for rows.Next() {
		if err := rows.Scan(&data); err != nil {
			log.Fatal(err)
		}

		address = append(address, data)
	}

	var result model.SigninFromPasswordResponse
	result.Address = address

	c.IndentedJSON(http.StatusOK, gin.H{
		"msg":    "OK",
		"result": result,
	})
}

func SigninFromMnemonic(c *gin.Context) {
	var body model.SigninFromMnemonicRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	wallet, err := hdWallet.NewFromMnemonic(body.Mnemonic)
	if err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{
			"msg": "mnemonic is not valid",
		})
	}

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

	var keyId int
	err = db.QueryRow("SELECT (keyId) FROM test_db.address WHERE address = ?", address).Scan(&keyId)

	if err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{
			"msg": "mnemonic is not valid",
		})
	}

	var data string
	var resultAddress []string
	rows, err := db.Query("SELECT address FROM test_db.address WHERE keyId = ?", keyId)

	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()

	for rows.Next() {
		if err := rows.Scan(&data); err != nil {
			log.Fatal(err)
		}

		resultAddress = append(resultAddress, data)
	}

	var mark string
	err = db.QueryRow("SELECT (mark) FROM test_db.key WHERE id = ?", keyId).Scan(&mark)
	if err != nil {
		log.Fatal(err)
	}

	var response model.SigninFromMnemonicResponse
	response.Address = resultAddress
	response.Mark = mark

	c.IndentedJSON(http.StatusOK, gin.H{
		"msg":    "OK",
		"result": response,
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
