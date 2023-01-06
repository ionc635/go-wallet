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
