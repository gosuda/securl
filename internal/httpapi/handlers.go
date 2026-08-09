package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"

	securlv1 "securl.click/securl/gen/go/securl/v1"
	"securl.click/securl/internal/access"
	"securl.click/securl/internal/captcha"
	"securl.click/securl/internal/safebrowsing"
	"securl.click/securl/internal/store"
)

const (
	createRequestLimit       = int64(16 << 10)
	accessRequestLimit       = int64(4 << 10)
	safeBrowsingRequestLimit = int64(4 << 10)
	knownFeatureFlags        = uint32(0x07)
)

func expirationTime(now time.Time, ttlSeconds uint32) time.Time {
	if ttlSeconds == 0 {
		return time.Time{}
	}
	return now.Add(time.Duration(ttlSeconds) * time.Second)
}

func expirationUnix(expiresAt time.Time) int64 {
	if expiresAt.IsZero() {
		return 0
	}
	return expiresAt.Unix()
}

func (handler *api) getConfig(writer http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	if handler.dependencies.RuntimeConfig == nil {
		writeError(writer, request, http.StatusInternalServerError, "internal", "Internal server error.")
		return
	}
	writer.Header().Set("Cache-Control", "private, no-store")
	writeMessage(writer, http.StatusOK, handler.dependencies.RuntimeConfig)
}

func validateMetadata(metadata *securlv1.EnvelopeMetadata, allowedTTLs map[uint32]struct{}) error {
	if metadata == nil || metadata.ProtocolVersion != 2 ||
		metadata.FeatureFlags&^knownFeatureFlags != 0 || len(metadata.PayloadNonce) != 24 {
		return store.ErrInvalid
	}
	if _, ok := allowedTTLs[metadata.TtlSeconds]; !ok {
		return store.ErrInvalid
	}
	passwordEnabled := metadata.FeatureFlags&uint32(securlv1.FeatureFlag_FEATURE_FLAG_PASSWORD) != 0
	if passwordEnabled != (metadata.Password != nil) {
		return store.ErrInvalid
	}
	if metadata.Password != nil &&
		(len(metadata.Password.Salt) != 16 || len(metadata.Password.Nonce) != 24 ||
			metadata.Password.Profile != securlv1.PasswordProfile_PASSWORD_PROFILE_ARGON2D_V1) {
		return store.ErrInvalid
	}
	captchaEnabled := metadata.FeatureFlags&uint32(securlv1.FeatureFlag_FEATURE_FLAG_CAPTCHA) != 0
	if captchaEnabled != (metadata.Captcha != nil) {
		return store.ErrInvalid
	}
	if metadata.Captcha != nil && len(metadata.Captcha.Nonce) != 24 {
		return store.ErrInvalid
	}
	return nil
}

func (handler *api) createEnvelope(
	writer http.ResponseWriter,
	request *http.Request,
	_ httprouter.Params,
) {
	var createRequest securlv1.CreateEnvelopeRequest
	if requestErr := readRequest(writer, request, createRequestLimit, &createRequest); requestErr != nil {
		writeError(writer, request, requestErr.status, requestErr.code, requestErr.message)
		return
	}
	if len(createRequest.StorageKey) != 16 || createRequest.Envelope == nil ||
		validateMetadata(createRequest.Envelope.Metadata, handler.dependencies.AllowedTTLs) != nil {
		writeError(writer, request, http.StatusBadRequest, "invalid_request", "Invalid envelope request.")
		return
	}
	metadata := createRequest.Envelope.Metadata
	captchaEnabled := metadata.FeatureFlags&uint32(securlv1.FeatureFlag_FEATURE_FLAG_CAPTCHA) != 0
	if captchaEnabled {
		if len(createRequest.CaptchaKey) != 32 || handler.dependencies.Access == nil ||
			handler.dependencies.RuntimeConfig == nil || handler.dependencies.CaptchaVerifier == nil ||
			handler.dependencies.CaptchaWrapper == nil ||
			handler.dependencies.RuntimeConfig.CaptchaProvider == securlv1.CaptchaProvider_CAPTCHA_PROVIDER_NONE {
			writeError(writer, request, http.StatusBadRequest, "feature_unavailable", "CAPTCHA protection is unavailable.")
			return
		}
		defer func() {
			for index := range createRequest.CaptchaKey {
				createRequest.CaptchaKey[index] = 0
			}
		}()
	} else if len(createRequest.CaptchaKey) != 0 {
		writeError(writer, request, http.StatusBadRequest, "invalid_request", "Unexpected CAPTCHA key.")
		return
	}

	envelopeBytes, err := createRequest.Envelope.MarshalVTStrict()
	if err != nil || len(envelopeBytes) == 0 || len(envelopeBytes) > handler.dependencies.MaxEnvelopeBytes ||
		len(createRequest.Envelope.Ciphertext) == 0 {
		writeError(writer, request, http.StatusBadRequest, "invalid_request", "Invalid envelope request.")
		return
	}
	metadataBytes, err := metadata.MarshalVTStrict()
	if err != nil {
		writeError(writer, request, http.StatusBadRequest, "invalid_request", "Invalid envelope metadata.")
		return
	}
	var storageKey [16]byte
	copy(storageKey[:], createRequest.StorageKey)
	requestHasher := sha256.New()
	_, _ = requestHasher.Write(storageKey[:])
	_, _ = requestHasher.Write(envelopeBytes)
	if captchaEnabled {
		_, _ = requestHasher.Write(createRequest.CaptchaKey)
	}
	var requestHash [32]byte
	copy(requestHash[:], requestHasher.Sum(nil))
	now := handler.dependencies.Now().UTC()
	existing, lookupErr := handler.dependencies.Repository.Get(request.Context(), storageKey, time.Unix(0, 0).UTC())
	if lookupErr == nil {
		if !bytes.Equal(existing.RequestHash[:], requestHash[:]) {
			handler.writeStoreError(writer, request, store.ErrConflict)
			return
		}
		writer.Header().Set("Cache-Control", "private, no-store")
		writeMessage(writer, http.StatusOK, &securlv1.CreateEnvelopeResponse{
			ExpiresAtUnix: expirationUnix(existing.ExpiresAt), Replayed: true,
		})
		return
	}
	if !errors.Is(lookupErr, store.ErrNotFound) {
		handler.writeStoreError(writer, request, lookupErr)
		return
	}
	createCaptchaRequired := handler.dependencies.RuntimeConfig != nil &&
		handler.dependencies.RuntimeConfig.CreateCaptchaRequired
	if createCaptchaRequired {
		if handler.dependencies.CaptchaVerifier == nil ||
			handler.dependencies.RuntimeConfig.CaptchaProvider == securlv1.CaptchaProvider_CAPTCHA_PROVIDER_NONE {
			writeError(writer, request, http.StatusBadRequest, "feature_unavailable", "CAPTCHA verification is unavailable.")
			return
		}
		if createRequest.CaptchaToken == "" {
			writeError(writer, request, http.StatusForbidden, "captcha_required", "CAPTCHA verification is required.")
			return
		}
		if verifyErr := handler.dependencies.CaptchaVerifier.Verify(request.Context(), createRequest.CaptchaToken); verifyErr != nil {
			handler.writeCaptchaError(writer, request, verifyErr)
			return
		}
	} else if createRequest.CaptchaToken != "" {
		writeError(writer, request, http.StatusBadRequest, "invalid_request", "Unexpected CAPTCHA token.")
		return
	}
	var wrappedNonce, wrappedCiphertext []byte
	if captchaEnabled {
		wrappedNonce, wrappedCiphertext, err = handler.dependencies.CaptchaWrapper.Wrap(
			storageKey, metadata.ProtocolVersion, createRequest.CaptchaKey,
		)
		if err != nil {
			writeError(writer, request, http.StatusInternalServerError, "internal", "Internal server error.")
			return
		}
	}
	envelopeHash := sha256.Sum256(envelopeBytes)
	etag := `"` + base64.RawURLEncoding.EncodeToString(envelopeHash[:]) + `"`
	expiresAt := expirationTime(now, metadata.TtlSeconds)
	result, err := handler.dependencies.Repository.Create(request.Context(), store.CreateInput{
		StorageKey:           storageKey,
		Metadata:             metadataBytes,
		Envelope:             envelopeBytes,
		RequestHash:          requestHash,
		ETag:                 etag,
		FeatureFlags:         metadata.FeatureFlags,
		ExpiresAt:            expiresAt,
		CaptchaKeyNonce:      wrappedNonce,
		CaptchaKeyCiphertext: wrappedCiphertext,
	})
	if err != nil {
		handler.writeStoreError(writer, request, err)
		return
	}
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	writer.Header().Set("Cache-Control", "private, no-store")
	writeMessage(writer, status, &securlv1.CreateEnvelopeResponse{
		ExpiresAtUnix: expirationUnix(result.ExpiresAt), Replayed: result.Replayed,
	})
}

func (handler *api) getEnvelopeMetadata(
	writer http.ResponseWriter,
	request *http.Request,
	params httprouter.Params,
) {
	storageKey, ok := parseStorageKey(params.ByName("storageKey"))
	if !ok {
		writeError(writer, request, http.StatusNotFound, "not_found", "Envelope not found.")
		return
	}
	record, err := handler.dependencies.Repository.GetMetadata(
		request.Context(), storageKey, handler.dependencies.Now().UTC(),
	)
	if err != nil {
		handler.writeStoreError(writer, request, err)
		return
	}
	var metadata securlv1.EnvelopeMetadata
	if err := decodeCanonical(record.Metadata, &metadata); err != nil {
		writeError(writer, request, http.StatusInternalServerError, "internal", "Internal server error.")
		return
	}
	writer.Header().Set("Cache-Control", "private, no-store")
	writeMessage(writer, http.StatusOK, &securlv1.GetEnvelopeMetadataResponse{
		Metadata: &metadata, ExpiresAtUnix: expirationUnix(record.ExpiresAt),
	})
}

func (handler *api) getEnvelope(
	writer http.ResponseWriter,
	request *http.Request,
	params httprouter.Params,
) {
	storageKey, ok := parseStorageKey(params.ByName("storageKey"))
	if !ok {
		writeError(writer, request, http.StatusNotFound, "not_found", "Envelope not found.")
		return
	}
	record, err := handler.dependencies.Repository.Get(
		request.Context(), storageKey, handler.dependencies.Now().UTC(),
	)
	if err != nil {
		handler.writeStoreError(writer, request, err)
		return
	}
	if record.FeatureFlags&(access.CaptchaFlag|access.BurnAfterReadFlag) != 0 {
		writeError(writer, request, http.StatusConflict, "access_required", "Protected access is required.")
		return
	}
	var envelope securlv1.Envelope
	if err := decodeCanonical(record.Envelope, &envelope); err != nil {
		writeError(writer, request, http.StatusInternalServerError, "internal", "Internal server error.")
		return
	}
	writer.Header().Set("ETag", record.ETag)
	writer.Header().Set("Cache-Control", "private, no-cache")
	if request.Header.Get("If-None-Match") == record.ETag {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	writeRawProtobuf(writer, http.StatusOK, record.Envelope)
}

func (handler *api) accessEnvelope(
	writer http.ResponseWriter,
	request *http.Request,
	params httprouter.Params,
) {
	var accessRequest securlv1.AccessEnvelopeRequest
	if requestErr := readRequest(writer, request, accessRequestLimit, &accessRequest); requestErr != nil {
		writeError(writer, request, requestErr.status, requestErr.code, requestErr.message)
		return
	}
	storageKey, ok := parseStorageKey(params.ByName("storageKey"))
	if !ok {
		writeError(writer, request, http.StatusNotFound, "not_found", "Envelope not found.")
		return
	}
	if handler.dependencies.Access == nil {
		writeError(writer, request, http.StatusBadRequest, "feature_unavailable", "Protected access is unavailable.")
		return
	}
	result, err := handler.dependencies.Access.Access(
		request.Context(), storageKey, handler.dependencies.Now().UTC(), accessRequest.CaptchaToken,
	)
	if err != nil {
		handler.writeAccessError(writer, request, err)
		return
	}
	var envelope securlv1.Envelope
	if err := decodeCanonical(result.Record.Envelope, &envelope); err != nil {
		for index := range result.CaptchaKey {
			result.CaptchaKey[index] = 0
		}
		writeError(writer, request, http.StatusInternalServerError, "internal", "Internal server error.")
		return
	}
	response := &securlv1.AccessEnvelopeResponse{
		Envelope: &envelope, CaptchaKey: result.CaptchaKey, ExpiresAtUnix: expirationUnix(result.Record.ExpiresAt),
	}
	body, err := response.MarshalVTStrict()
	for index := range result.CaptchaKey {
		result.CaptchaKey[index] = 0
	}
	if err != nil {
		writeError(writer, request, http.StatusInternalServerError, "internal", "Internal server error.")
		return
	}
	writer.Header().Set("Cache-Control", "private, no-store")
	writeRawProtobuf(writer, http.StatusOK, body)
}

func (handler *api) safeBrowsingLookup(
	writer http.ResponseWriter,
	request *http.Request,
	_ httprouter.Params,
) {
	if handler.dependencies.SafeBrowsing == nil {
		writeError(writer, request, http.StatusBadRequest, "feature_unavailable", "Safety checking is unavailable.")
		return
	}
	var lookupRequest securlv1.SafeBrowsingLookupRequest
	if requestErr := readRequest(writer, request, safeBrowsingRequestLimit, &lookupRequest); requestErr != nil {
		writeError(writer, request, requestErr.status, requestErr.code, requestErr.message)
		return
	}
	if len(lookupRequest.HashPrefixes) < 1 || len(lookupRequest.HashPrefixes) > safebrowsing.MaxPrefixes {
		writeError(writer, request, http.StatusBadRequest, "invalid_request", "Invalid hash prefixes.")
		return
	}
	prefixes := make([][4]byte, len(lookupRequest.HashPrefixes))
	for index, prefix := range lookupRequest.HashPrefixes {
		if len(prefix) != 4 {
			writeError(writer, request, http.StatusBadRequest, "invalid_request", "Invalid hash prefixes.")
			return
		}
		copy(prefixes[index][:], prefix)
	}
	result, err := handler.dependencies.SafeBrowsing.Lookup(request.Context(), prefixes)
	if err != nil {
		handler.writeSafeBrowsingError(writer, request, err)
		return
	}
	response := &securlv1.SafeBrowsingLookupResponse{
		FullHashes: make([]*securlv1.SafeBrowsingFullHash, 0, len(result.FullHashes)),
	}
	for _, fullHash := range result.FullHashes {
		response.FullHashes = append(response.FullHashes, &securlv1.SafeBrowsingFullHash{
			FullHash: fullHash.Hash[:], ThreatType: fullHash.ThreatType,
			Attributes: append([]string(nil), fullHash.Attributes...), CacheSeconds: fullHash.CacheSeconds,
		})
	}
	writer.Header().Set("Cache-Control", "private, no-store")
	writeMessage(writer, http.StatusOK, response)
}

func (handler *api) health(writer http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte("ok\n"))
}

func (handler *api) ready(writer http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	if handler.dependencies.Repository == nil || handler.dependencies.Repository.Ping(request.Context()) != nil {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte("not ready\n"))
		return
	}
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte("ready\n"))
}

func (handler *api) options(writer http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	writer.WriteHeader(http.StatusNoContent)
}

func (handler *api) methodNotAllowed(writer http.ResponseWriter, request *http.Request) {
	writeError(writer, request, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed.")
}

func (handler *api) notFound(writer http.ResponseWriter, request *http.Request) {
	if strings.HasPrefix(request.URL.Path, "/api/") {
		writeError(writer, request, http.StatusNotFound, "not_found", "Resource not found.")
		return
	}
	http.NotFound(writer, request)
}

func (handler *api) writeStoreError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(writer, request, http.StatusNotFound, "not_found", "Envelope not found.")
	case errors.Is(err, store.ErrConflict):
		writeError(writer, request, http.StatusConflict, "conflict", "Storage key conflict.")
	case errors.Is(err, store.ErrInvalid):
		writeError(writer, request, http.StatusBadRequest, "invalid_request", "Invalid storage request.")
	default:
		writeError(writer, request, http.StatusInternalServerError, "internal", "Internal server error.")
	}
}

func (handler *api) writeCaptchaError(writer http.ResponseWriter, request *http.Request, err error) bool {
	switch {
	case errors.Is(err, captcha.ErrCaptchaFailed):
		writeError(writer, request, http.StatusForbidden, "captcha_failed", "CAPTCHA verification failed.")
	case errors.Is(err, captcha.ErrRateLimited):
		writer.Header().Set("Retry-After", "1")
		writeError(writer, request, http.StatusTooManyRequests, "rate_limited", "CAPTCHA verifier is busy.")
	case errors.Is(err, captcha.ErrDependencyUnavailable):
		writeError(writer, request, http.StatusServiceUnavailable, "dependency_unavailable", "CAPTCHA verifier is unavailable.")
	case errors.Is(err, captcha.ErrFeatureUnavailable):
		writeError(writer, request, http.StatusBadRequest, "feature_unavailable", "CAPTCHA protection is unavailable.")
	default:
		return false
	}
	return true
}

func (handler *api) writeAccessError(writer http.ResponseWriter, request *http.Request, err error) {
	if handler.writeCaptchaError(writer, request, err) {
		return
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(writer, request, http.StatusNotFound, "not_found", "Envelope not found.")
	case errors.Is(err, access.ErrInvalidAccessRecord):
		writeError(writer, request, http.StatusBadRequest, "invalid_request", "Invalid protected access request.")
	default:
		writeError(writer, request, http.StatusInternalServerError, "internal", "Internal server error.")
	}
}

func (handler *api) writeSafeBrowsingError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, safebrowsing.ErrInvalidRequest):
		writeError(writer, request, http.StatusBadRequest, "invalid_request", "Invalid hash prefixes.")
	case errors.Is(err, safebrowsing.ErrRateLimited):
		writer.Header().Set("Retry-After", "1")
		writeError(writer, request, http.StatusTooManyRequests, "rate_limited", "Safety checker is busy.")
	default:
		writeError(writer, request, http.StatusServiceUnavailable, "dependency_unavailable", "Safety checker is unavailable.")
	}
}
