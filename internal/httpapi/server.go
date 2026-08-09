package httpapi

import (
	stdlog "log"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

type errorLogWriter struct {
	logger *zerolog.Logger
}

func (writer errorLogWriter) Write(message []byte) (int, error) {
	length := len(message)
	if length > 0 && message[length-1] == '\n' {
		message = message[:length-1]
	}
	writer.logger.Error().Msg(string(message))
	return length, nil
}

func NewServer(handler http.Handler, logger *zerolog.Logger) *http.Server {
	if logger == nil {
		nopLogger := zerolog.Nop()
		logger = &nopLogger
	}
	return &http.Server{
		Handler:           handler,
		ErrorLog:          stdlog.New(errorLogWriter{logger: logger}, "", 0),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}
