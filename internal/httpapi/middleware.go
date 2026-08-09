package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
)

const (
	allowedMethods = "GET,POST,OPTIONS"
	allowedHeaders = "Content-Type,If-None-Match"
	exposedHeaders = "ETag,Retry-After"
)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (writer *statusWriter) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *statusWriter) Write(body []byte) (int, error) {
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(body)
}

func (writer *statusWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

func middleware(dependencies Dependencies, next http.Handler) http.Handler {
	return http.HandlerFunc(func(originalWriter http.ResponseWriter, request *http.Request) {
		started := time.Now()
		writer := &statusWriter{ResponseWriter: originalWriter}
		requestIDBytes := make([]byte, 16)
		if _, err := rand.Read(requestIDBytes); err != nil {
			requestIDBytes = []byte("request-id-unavailable")
		}
		requestID := base64.RawURLEncoding.EncodeToString(requestIDBytes)
		request.Header.Set("X-Request-ID", requestID)
		writer.Header().Set("X-Request-ID", requestID)
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		writer.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if dependencies.EnableHSTS {
			writer.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}

		defer func() {
			if recover() != nil && writer.status == 0 {
				writeError(
					writer, request, http.StatusInternalServerError, "internal", "Internal server error.",
				)
			}
			status := writer.status
			if status == 0 {
				status = http.StatusOK
			}
			route := request.Pattern
			if route == "" {
				route = "unmatched"
			}
			dependencies.Logger.Info().
				Str("route", route).
				Int("status", status).
				Dur("duration", time.Since(started)).
				Str("request_id", requestID).
				Msg("request completed")
		}()

		originValues := request.Header.Values("Origin")
		origin := ""
		if len(originValues) == 1 {
			origin = originValues[0]
		} else if len(originValues) > 1 {
			writeError(writer, request, http.StatusForbidden, "invalid_request", "Origin is not allowed.")
			return
		}
		originAllowed := origin != "" &&
			(containsOrigin(dependencies.PublicOrigins, origin) ||
				containsOrigin(dependencies.CORSAllowedOrigins, origin))
		if origin != "" {
			appendVary(writer.Header(), "Origin")
		}
		if originAllowed {
			writer.Header().Set("Access-Control-Allow-Origin", origin)
			writer.Header().Set("Access-Control-Allow-Methods", allowedMethods)
			writer.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
			writer.Header().Set("Access-Control-Expose-Headers", exposedHeaders)
		}

		if request.Method == http.MethodOptions {
			if !originAllowed || !validPreflight(request) {
				writeError(writer, request, http.StatusForbidden, "invalid_request", "CORS preflight is not allowed.")
				return
			}
		} else if origin != "" && request.Method != http.MethodGet && !originAllowed {
			writeError(writer, request, http.StatusForbidden, "invalid_request", "Origin is not allowed.")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func containsOrigin(origins map[string]struct{}, origin string) bool {
	_, ok := origins[origin]
	return ok
}

func validPreflight(request *http.Request) bool {
	method := request.Header.Get("Access-Control-Request-Method")
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodOptions {
		return false
	}
	for _, header := range strings.Split(request.Header.Get("Access-Control-Request-Headers"), ",") {
		header = strings.ToLower(strings.TrimSpace(header))
		if header == "" {
			continue
		}
		if header != "content-type" && header != "if-none-match" {
			return false
		}
	}
	return true
}

func appendVary(header http.Header, value string) {
	for _, existing := range header.Values("Vary") {
		for _, item := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(item), value) {
				return
			}
		}
	}
	header.Add("Vary", value)
}
