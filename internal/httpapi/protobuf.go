package httpapi

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	securlv1 "securl.click/securl/gen/go/securl/v1"
)

const protobufContentType = "application/x-protobuf"

type strictMessage interface {
	MarshalVTStrict() ([]byte, error)
	UnmarshalVT([]byte) error
	ProtoReflect() protoreflect.Message
}

type responseMessage interface {
	MarshalVTStrict() ([]byte, error)
}

type requestError struct {
	status  int
	code    string
	message string
}

func (requestError *requestError) Error() string {
	return requestError.code
}

func hasUnknownFields(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	hasUnknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.IsList() && field.Kind() == protoreflect.MessageKind {
			list := value.List()
			for index := range list.Len() {
				if hasUnknownFields(list.Get(index).Message()) {
					hasUnknown = true
					return false
				}
			}
		} else if field.Kind() == protoreflect.MessageKind && hasUnknownFields(value.Message()) {
			hasUnknown = true
			return false
		}
		return true
	})
	return hasUnknown
}

func decodeCanonical(body []byte, message strictMessage) error {
	if err := message.UnmarshalVT(body); err != nil {
		return err
	}
	if hasUnknownFields(message.ProtoReflect()) {
		return errors.New("unknown protobuf field")
	}
	canonical, err := message.MarshalVTStrict()
	if err != nil {
		return err
	}
	if !bytes.Equal(body, canonical) {
		return errors.New("non-canonical protobuf message")
	}
	return nil
}

func readRequest(
	writer http.ResponseWriter,
	request *http.Request,
	maxBytes int64,
	message strictMessage,
) *requestError {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != protobufContentType {
		return &requestError{
			status: http.StatusUnsupportedMediaType, code: "unsupported_media_type",
			message: "Content-Type must be application/x-protobuf.",
		}
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return &requestError{
				status: http.StatusRequestEntityTooLarge, code: "content_too_large",
				message: "Request body is too large.",
			}
		}
		return &requestError{
			status: http.StatusBadRequest, code: "invalid_request", message: "Invalid request body.",
		}
	}
	if err := decodeCanonical(body, message); err != nil {
		return &requestError{
			status: http.StatusBadRequest, code: "invalid_request", message: "Invalid protobuf request.",
		}
	}
	return nil
}

func writeMessage(writer http.ResponseWriter, status int, message responseMessage) {
	body, err := message.MarshalVTStrict()
	if err != nil {
		writeError(writer, nil, http.StatusInternalServerError, "internal", "Internal server error.")
		return
	}
	writer.Header().Set("Content-Type", protobufContentType)
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

func writeRawProtobuf(writer http.ResponseWriter, status int, body []byte) {
	writer.Header().Set("Content-Type", protobufContentType)
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

func writeError(
	writer http.ResponseWriter,
	request *http.Request,
	status int,
	code string,
	message string,
) {
	requestID := ""
	if request != nil {
		requestID = request.Header.Get("X-Request-ID")
	}
	body, err := (&securlv1.ErrorResponse{
		Code: code, Message: message, RequestId: requestID,
	}).MarshalVTStrict()
	if err != nil {
		http.Error(writer, "internal", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", protobufContentType)
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

func parseStorageKey(encoded string) ([16]byte, bool) {
	var storageKey [16]byte
	if len(encoded) != 22 || strings.Contains(encoded, "=") {
		return storageKey, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != len(storageKey) ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return storageKey, false
	}
	copy(storageKey[:], decoded)
	return storageKey, true
}
