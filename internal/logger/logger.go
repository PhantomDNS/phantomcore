package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

func configureLogger() *logrus.Logger {
	log := logrus.New()
	log.SetOutput(os.Stdout)
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetLevel(logrus.InfoLevel)
	return log
}

var Log = configureLogger()
