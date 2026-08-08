package httpapi

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/julienschmidt/httprouter"

	securlv1 "securl.click/securl/gen/go/securl/v1"
	"securl.click/securl/internal/access"
	"securl.click/securl/internal/captcha"
	"securl.click/securl/internal/safebrowsing"
	"securl.click/securl/internal/store"
)

type Dependencies struct {
	Repository         store.Repository
	Access             *access.Service
	CaptchaWrapper     *captcha.KeyWrapper
	SafeBrowsing       safebrowsing.LookupClient
	RuntimeConfig      *securlv1.RuntimeConfig
	AllowedTTLs        map[uint32]struct{}
	MaxEnvelopeBytes   int
	Now                func() time.Time
	Frontend           http.Handler
	PublicOrigins      map[string]struct{}
	CORSAllowedOrigins map[string]struct{}
	EnableHSTS         bool
	Logger             *slog.Logger
}

type api struct {
	dependencies Dependencies
}

func NewRouter(dependencies Dependencies) http.Handler {
	if dependencies.MaxEnvelopeBytes <= 0 {
		dependencies.MaxEnvelopeBytes = 16384
	}
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	if dependencies.Logger == nil {
		dependencies.Logger = slog.Default()
	}
	handler := &api{dependencies: dependencies}
	router := httprouter.New()
	router.RedirectTrailingSlash = false
	router.RedirectFixedPath = false
	router.HandleMethodNotAllowed = true

	router.GET("/api/v1/config", route("/api/v1/config", handler.getConfig))
	router.POST("/api/v1/envelopes", route("/api/v1/envelopes", handler.createEnvelope))
	router.GET(
		"/api/v1/envelopes/:storageKey/metadata",
		route("/api/v1/envelopes/:storageKey/metadata", handler.getEnvelopeMetadata),
	)
	router.GET(
		"/api/v1/envelopes/:storageKey",
		route("/api/v1/envelopes/:storageKey", handler.getEnvelope),
	)
	router.POST(
		"/api/v1/envelopes/:storageKey/access",
		route("/api/v1/envelopes/:storageKey/access", handler.accessEnvelope),
	)
	router.POST(
		"/api/v1/safe-browsing/lookup",
		route("/api/v1/safe-browsing/lookup", handler.safeBrowsingLookup),
	)
	router.GET("/healthz", route("/healthz", handler.health))
	router.GET("/readyz", route("/readyz", handler.ready))
	router.OPTIONS("/*path", route("OPTIONS /*path", handler.options))
	router.MethodNotAllowed = http.HandlerFunc(handler.methodNotAllowed)
	if dependencies.Frontend != nil {
		router.NotFound = dependencies.Frontend
	} else {
		router.NotFound = http.HandlerFunc(handler.notFound)
	}
	return middleware(dependencies, router)
}

func route(pattern string, handler httprouter.Handle) httprouter.Handle {
	return func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		request.Pattern = pattern
		handler(writer, request, params)
	}
}
