package model

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
