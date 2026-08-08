package frontend

import (
	"bytes"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
)

type Handler struct {
	files fs.FS
	csp   string
}

func NewHandler() (*Handler, error) {
	files, err := fs.Sub(distribution, "dist")
	if err != nil {
		return nil, err
	}
	return newHandler(files)
}

func newHandler(files fs.FS) (*Handler, error) {
	index, err := fs.ReadFile(files, "index.html")
	if err != nil {
		return nil, fmt.Errorf("read embedded index: %w", err)
	}
	return &Handler{files: files, csp: extractCSP(index)}, nil
}

func extractCSP(index []byte) string {
	const marker = `<meta http-equiv="content-security-policy" content="`
	start := bytes.Index(index, []byte(marker))
	if start < 0 {
		return ""
	}
	value := index[start+len(marker):]
	end := bytes.Index(value, []byte(`">`))
	if end < 0 {
		return ""
	}
	return string(value[:end]) + "; frame-ancestors 'none'"
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestedPath := request.URL.Path
	filePath := "index.html"
	if requestedPath != "/" {
		filePath = strings.TrimPrefix(requestedPath, "/")
		if filePath == "" || path.Clean(filePath) != filePath || strings.Contains(filePath, `\`) {
			http.NotFound(writer, request)
			return
		}
	}
	info, err := fs.Stat(handler.files, filePath)
	if err != nil || info.IsDir() {
		http.NotFound(writer, request)
		return
	}

	servedPath := filePath
	encoding := ""
	if acceptsEncoding(request.Header.Get("Accept-Encoding"), "br") {
		if _, err := fs.Stat(handler.files, filePath+".br"); err == nil {
			servedPath = filePath + ".br"
			encoding = "br"
		}
	}
	if encoding == "" && acceptsEncoding(request.Header.Get("Accept-Encoding"), "gzip") {
		if _, err := fs.Stat(handler.files, filePath+".gz"); err == nil {
			servedPath = filePath + ".gz"
			encoding = "gzip"
		}
	}
	body, err := fs.ReadFile(handler.files, servedPath)
	if err != nil {
		http.NotFound(writer, request)
		return
	}

	writer.Header().Set("Vary", "Accept-Encoding")
	if encoding != "" {
		writer.Header().Set("Content-Encoding", encoding)
	}
	if contentType := mime.TypeByExtension(path.Ext(filePath)); contentType != "" {
		writer.Header().Set("Content-Type", contentType)
	}
	if filePath == "index.html" {
		writer.Header().Set("Cache-Control", "no-cache")
		if handler.csp != "" {
			writer.Header().Set("Content-Security-Policy", handler.csp)
		}
	} else if strings.HasPrefix(requestedPath, "/_app/immutable/") {
		writer.Header().Set("Cache-Control", "public,max-age=31536000,immutable")
	} else {
		writer.Header().Set("Cache-Control", "no-cache")
	}
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(http.StatusOK)
	if request.Method == http.MethodGet {
		_, _ = writer.Write(body)
	}
}

func acceptsEncoding(header, target string) bool {
	for _, item := range strings.Split(header, ",") {
		parts := strings.Split(strings.TrimSpace(item), ";")
		if strings.TrimSpace(parts[0]) != target && strings.TrimSpace(parts[0]) != "*" {
			continue
		}
		accepted := true
		for _, parameter := range parts[1:] {
			parameter = strings.TrimSpace(parameter)
			if strings.HasPrefix(parameter, "q=") {
				quality, err := strconv.ParseFloat(strings.TrimPrefix(parameter, "q="), 64)
				if err != nil || quality <= 0 {
					accepted = false
				}
			}
		}
		return accepted
	}
	return false
}
