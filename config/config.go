package config

import (
	"os"

	"github.com/naoina/toml"
)

type Config struct {
	Rpc struct {
		GoerliAPI  string
		MainnetAPI string
	}

	Wallet struct {
		PrivateKey string
		Address    string
	}

	Etherscan struct {
		GoerliAPI  string
		MainnetAPI string
		ApiKey     string
	}

	Mysql struct {
		User   string
		Passwd string
		Addr   string
		DBName string
	}
}

func GetConfig(fpath string) *Config {
	c := new(Config)

	if file, err := os.Open(fpath); err != nil {
		panic(err)
	} else {
		defer file.Close()

		if err := toml.NewDecoder(file).Decode(c); err != nil {
			panic(err)
		} else {
			return c
		}
	}
}
