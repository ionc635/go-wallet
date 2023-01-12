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
	rows, err := db.Query("SELECT address FROM test_db.address WHERE keyId = ? AND isUsed = true", id)

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

	// 니모닉으로부터 지갑 생성
	wallet, err := hdWallet.NewFromMnemonic(body.Mnemonic)
	if err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{
			"msg": "mnemonic is not valid",
		})
	}

	// coinType 확인
	client := rpc.NewRpcClient()
	// 이더리움 coin_type / main_net - 60, test_net - 1 /
	var coinType int = 60
	if chainId, _ := client.NetworkID(context.Background()); chainId != big.NewInt(1) {
		coinType = 1
	}

	// 0번째 path로 Address 생성
	path := hdWallet.MustParseDerivationPath("m/44'/" + fmt.Sprintf("%v", coinType) + "'/0'/0/0")
	account, _ := wallet.Derive(path, true)
	address := account.Address.Hex()

	// 해당 Address로 keyId 조회
	db := db.GetConnector()
	var keyId int
	err = db.QueryRow("SELECT (keyId) FROM test_db.address WHERE address = ?", address).Scan(&keyId)

	if err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{
			"msg": "mnemonic is not valid",
		})
	}

	// 해당 keyId로 매핑되어 있는 타 주소 조회
	var data string
	var resultAddress []string
	rows, err := db.Query("SELECT address FROM test_db.address WHERE keyId = ? AND isUsed = true", keyId)

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

	// mark 조회
	var mark string
	err = db.QueryRow("SELECT (mark) FROM test_db.key WHERE id = ?", keyId).Scan(&mark)
	if err != nil {
		log.Fatal(err)
	}

	var result model.SigninFromMnemonicResponse
	result.Address = resultAddress
	result.Mark = mark

	c.IndentedJSON(http.StatusOK, gin.H{
		"msg":    "OK",
		"result": result,
	})
}

func AddWallet(c *gin.Context) {
	mark := c.Param("mark")

	// 니모닉 조회
	db := db.GetConnector()
	var mnemonic string
	var keyId string
	db.QueryRow("SELECT id, AES_DECRYPT(unhex(mnemonic), ?) FROM test_db.key WHERE mark = ?", mark, mark).Scan(&keyId, &mnemonic)

	// coinType 확인
	client := rpc.NewRpcClient()
	// 이더리움 coin_type / main_net - 60, test_net - 1 /
	var coinType int = 60
	if chainId, _ := client.NetworkID(context.Background()); chainId != big.NewInt(1) {
		coinType = 1
	}

	// 해당 keyId로 몇번째 지갑인지 확인
	rows, err := db.Query("SELECT COUNT(*) FROM test_db.address WHERE keyId = ?", keyId)

	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()

	var count int

	for rows.Next() {
		if err := rows.Scan(&count); err != nil {
			log.Fatal(err)
		}
	}

	// 지갑 생성
	wallet, _ := hdWallet.NewFromMnemonic(mnemonic)

	// BIP44
	path := hdWallet.MustParseDerivationPath("m/44'/" + fmt.Sprintf("%v", coinType) + "'/0'/0/" + fmt.Sprintf("%v", count))
	account, _ := wallet.Derive(path, true)

	// privateKey, address 생성
	privateKey, _ := wallet.PrivateKeyHex(account)
	address := account.Address.Hex()

	// DB 저장
	_, err = db.Exec("INSERT INTO test_db.address (address, privateKey, keyId, level, type) VALUES (?, hex(aes_encrypt(?, ?)), ?, ?, ?)", address, privateKey, mark, keyId, count, coinType)
	if err != nil {
		log.Fatal(err)
	}

	var result model.AddWalletResponse
	result.Address = address

	c.IndentedJSON(http.StatusOK, gin.H{
		"msg":    "OK",
		"result": result,
	})
}

func RemoveWallet(c *gin.Context) {
	var body model.RemoveWalletRequest
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

	// isUsed 상태 값 false로 변경
	_, err = db.Exec("UPDATE test_db.address SET isUsed = false WHERE address = ?", body.Address)
	if err != nil {
		log.Fatal(err)
	}

	c.IndentedJSON(http.StatusOK, gin.H{
		"msg": "OK",
	})
}

func GetWallets(c *gin.Context) {
	mark := c.Param("mark")

	// mark로 id 조회
	db := db.GetConnector()
	var id int
	err := db.QueryRow("SELECT (id) FROM test_db.key WHERE mark = ?", mark).Scan(&id)
	if err != nil {
		log.Fatal(err)
	}

	// 해당 keyId로 매핑되어 있는 타 주소 조회
	var data string
	var address []string
	rows, err := db.Query("SELECT address FROM test_db.address WHERE keyId = ? AND isUsed = true", id)

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

	var result model.GetWalletsResponse
	result.Address = address

	c.IndentedJSON(http.StatusOK, gin.H{
		"msg":    "OK",
		"result": result,
	})
}

func GetWallet(c *gin.Context) {
	address := c.Param("address")

	// RPC 연결
	client := rpc.NewRpcClient()

	account := common.HexToAddress(address)

	// 밸런즈 조회
	balance, err := client.BalanceAt(context.Background(), account, nil)

	if err != nil {
		log.Fatal(err)
		return
	}

	// 트랜잭션 조회 API
	url := "/api?module=account&action=txlist&address=" + fmt.Sprintf("%v", address) + "&startblock=0&endblock=99999999&page=0&offset=9999&sort=desc&apikey="

	// 이더스캔 연결
	resp, err := scan.NewHttpRequest(url)

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var transactions model.GetTransactions
	if err = json.Unmarshal(data, &transactions); err != nil {
		log.Fatal(err)
	}

	var result model.GetWalletResponse
	result.Balance = balance
	result.Transactions = transactions

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
