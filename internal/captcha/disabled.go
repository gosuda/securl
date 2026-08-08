package captcha

import "context"

type DisabledVerifier struct{}

func NewDisabledVerifier() Verifier {
	return DisabledVerifier{}
}

func (DisabledVerifier) Verify(context.Context, string) error {
	return ErrFeatureUnavailable
}
