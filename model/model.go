package model

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

type NewMnemonicAndWalletResponse struct {
	Mnemonic string `json:"mnemonic"`
	Address  string `json:"address"`
	Token    string `json:"token"`
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

type NewMnemonicRequest struct {
	Password string `json:"password"`
}

type SigninFromPasswordRequest struct {
	Password string `json:"password"`
}

type SigninFromMnemonicRequest struct {
	Mnemonic string `json:"mnemonic"`
}

type SigninFromMnemonicResponse struct {
	Address []string `json:"address"`
	Mark    string   `json:"mark"`
}

type SigninFromPasswordResponse struct {
	Address []string `json:"address"`
}

type AddWalletResponse struct {
	Address string `json:"address"`
}

type RemoveWalletRequest struct {
	Address  string `json:"address"`
	Password string `json:"password"`
}

type GetWalletsResponse struct {
	Address []string `json:"address"`
}

type GetWalletResponse struct {
	Balance      *big.Int        `json:"balance"`
	Transactions GetTransactions `json:"transactions"`
}
