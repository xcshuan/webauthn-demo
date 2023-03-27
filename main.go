package main

import (
	"github.com/sirupsen/logrus"
	"webauthn/pkg/api"
)

func main() {
	logrus.SetLevel(logrus.DebugLevel)

	s, err := api.NewServer("localhost:8080")
	if err != nil {
		logrus.WithError(err).Fatal("fatal error")
	}

	s.Start()
}
