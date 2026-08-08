package frontend

import (
	"errors"
	"net/http"
)

func ForMode(mode string) (http.Handler, error) {
	return forMode(mode, func() (http.Handler, error) { return NewHandler() })
}

func forMode(mode string, embedded func() (http.Handler, error)) (http.Handler, error) {
	switch mode {
	case "embedded":
		return embedded()
	case "external":
		return nil, nil
	default:
		return nil, errors.New("frontend mode must be embedded or external")
	}
}
