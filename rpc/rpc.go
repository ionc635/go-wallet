package rpc

import (
	"log"

	conf "lecture/go-wallet/config"

	"github.com/ethereum/go-ethereum/ethclient"
)

var config = conf.GetConfig("config/config.toml")

var (
	GOERLI_API_KEY  = config.Rpc.GoerliAPI
	MAINNET_API_KEY = config.Rpc.MainnetAPI
)

func NewRpcClient() *ethclient.Client {
	client, err := ethclient.Dial(GOERLI_API_KEY)

	if err != nil {
		log.Fatalf("Could not connect to Infura: %v", err)

	}

	return client
}
