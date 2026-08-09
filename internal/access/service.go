package access

import (
	"context"
	"errors"
	"time"

	"securl.click/securl/internal/captcha"
	"securl.click/securl/internal/store"
)

const (
	CaptchaFlag       = uint32(0x01)
	BurnAfterReadFlag = uint32(0x04)
)

var ErrInvalidAccessRecord = errors.New("access: invalid record")

type Result struct {
	Record     store.Record
	CaptchaKey []byte
}

type Service struct {
	repository store.Repository
	verifier   captcha.Verifier
	wrapper    *captcha.KeyWrapper
}

func NewService(repository store.Repository, verifier captcha.Verifier, wrapper *captcha.KeyWrapper) *Service {
	return &Service{repository: repository, verifier: verifier, wrapper: wrapper}
}

func (service *Service) Access(
	ctx context.Context,
	storageKey [16]byte,
	now time.Time,
	captchaToken string,
) (Result, error) {
	record, err := service.repository.Get(ctx, storageKey, now)
	if err != nil {
		return Result{}, err
	}
	captchaEnabled := record.FeatureFlags&CaptchaFlag != 0
	burnAfterRead := record.FeatureFlags&BurnAfterReadFlag != 0
	if !captchaEnabled && !burnAfterRead {
		return Result{}, ErrInvalidAccessRecord
	}
	if !captchaEnabled && captchaToken != "" {
		return Result{}, ErrInvalidAccessRecord
	}
	if captchaEnabled {
		if service.verifier == nil || service.wrapper == nil || len(record.CaptchaKeyNonce) != 12 ||
			len(record.CaptchaKeyCiphertext) == 0 {
			return Result{}, ErrInvalidAccessRecord
		}
		if err := service.verifier.Verify(ctx, captchaToken); err != nil {
			return Result{}, err
		}
	} else if len(record.CaptchaKeyNonce) != 0 || len(record.CaptchaKeyCiphertext) != 0 {
		return Result{}, ErrInvalidAccessRecord
	}

	if burnAfterRead {
		record, err = service.repository.Consume(ctx, storageKey, now)
		if err != nil {
			return Result{}, err
		}
	}

	var captchaKey []byte
	if captchaEnabled {
		captchaKey, err = service.wrapper.Unwrap(
			storageKey,
			2,
			record.CaptchaKeyNonce,
			record.CaptchaKeyCiphertext,
		)
		if err != nil {
			return Result{}, err
		}
	}
	return Result{Record: record, CaptchaKey: captchaKey}, nil
}
