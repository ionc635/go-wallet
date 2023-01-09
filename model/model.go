package model

import (
	"github.com/ethereum/go-ethereum/common"
)

type NewMnemonicResponse struct {
	Mnemonic string `json:"mnemonic"`
}

type CreateWalletRequest struct {
	Mnemonic string `json:"mnemonic" binding:"required"`
}

type NewWalletResponse struct {
	PrivateKey string `json:"privateKey"`
	Address    string `json:"address"`
}

type CheckValidRequest struct {
	Address string `json:"address"`
}

type TransferETHRequest struct {
	ToAddress common.Address `json:"toAddress"`
	Amount    int64          `json:"amount"`
}

type GetTransactions struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Result  []struct {
		BlockNumber       string `json:"blockNumber"`
		TimeStamp         string `json:"timeStamp"`
		Hash              string `json:"hash"`
		Nonce             string `json:"nonce"`
		BlockHash         string `json:"blockHash"`
		TransactionIndex  string `json:"transactionIndex"`
		From              string `json:"from"`
		To                string `json:"to"`
		Value             string `json:"value"`
		Gas               string `json:"gas"`
		GasPrice          string `json:"gasPrice"`
		IsError           string `json:"isError"`
		Txreceipt_status  string `json:"txreceipt_status"`
		Input             string `json:"input"`
		ContractAddress   string `json:"contractAddress"`
		CumulativeGasUsed string `json:"cumulativeGasUsed"`
		GasUsed           string `json:"gasUsed"`
		Confirmations     string `json:"confirmations"`
		MethodId          string `json:"methodId"`
		FunctionName      string `json:"functionName"`
	}
}

type GetTransactionStatusRequest struct {
	Hash common.Hash `json:"hash"`
}

type GetTransactionStatus struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Result  struct {
		IsError        string `json:"isError"`
		ErrDescription string `json:"errDescription"`
	}
}

// type TxData interface {
// 	txType() byte // returns the type ID
// 	copy() TxData // creates a deep copy and initializes all fields

// 	chainID() *big.Int
// 	data() []byte
// 	gas() uint64
// 	gasPrice() *big.Int
// 	gasTipCap() *big.Int
// 	gasFeeCap() *big.Int
// 	value() *big.Int
// 	nonce() uint64
// 	to() *common.Address

// 	rawSignatureValues() (v, r, s *big.Int)
// 	setSignatureValues(chainID, v, r, s *big.Int)
// }
