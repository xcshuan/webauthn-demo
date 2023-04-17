package main

import (
	"webauthn/pkg/api"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.SetLevel(logrus.DebugLevel)
	client, err := ethclient.Dial("http://127.0.0.1:8545")
	if err != nil {
		logrus.WithError(err).Fatal("fatal error")
	}

	s, err := api.NewServer("localhost:8080", client, common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3"), "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	if err != nil {
		logrus.WithError(err).Fatal("fatal error")
	}

	s.Start()
}
