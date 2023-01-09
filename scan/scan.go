package scan

import (
	conf "lecture/go-wallet/config"
	"log"
	"net/http"
)

var config = conf.GetConfig("config/config.toml")

var (
	GOERLI_API        = config.Etherscan.GoerliAPI
	MAINNET_API       = config.Etherscan.MainnetAPI
	ETHERSCAN_API_KEY = config.Etherscan.ApiKey
)

func NewHttpRequest(url string) (resp *http.Response, err error) {
	resp, err = http.Get(GOERLI_API + url + ETHERSCAN_API_KEY)

	if err != nil {
		log.Fatalf("Could not connect to Infura: %v", err)

	}

	return resp, err
}
