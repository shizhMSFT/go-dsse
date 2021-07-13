package dsse

import "errors"

var (
	ErrMissingSigner   = errors.New("dsse: missing signer")
	ErrMissingVerifier = errors.New("dsse: missing verifier")
	ErrVerification    = errors.New("dsse: verification error")
)
