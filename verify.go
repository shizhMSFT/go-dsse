package dsse

// Verifier verifies the envelope
type Verifier interface {
	// Verify verifiers if the signature is for the message.
	// Return nil if valid.
	Verify(message, signature []byte) error

	// KeyID returns the key ID of the verification key.
	// Empty if not supported.
	KeyID() string
}

// SignVerifier is not only a verifier but also a signer.
type SignVerifier interface {
	Signer
	Verifier
}

// EnvelopeVerifier is a group of verifiers.
type EnvelopeVerifier []Verifier

// NewEnvelopeVerifier wraps verifiers to be an envelope verifier.
func NewEnvelopeVerifier(verifiers ...Verifier) EnvelopeVerifier {
	return verifiers
}

// Verify verifies the envelope.
// Returns a list of verifiers recognizing the signautre and nil error.
// Reference:
//  - https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
//  - https://github.com/secure-systems-lab/dsse/blob/master/implementation/signing_spec.py
func (v EnvelopeVerifier) Verify(e *Envelope) ([]Verifier, error) {
	if len(v) == 0 {
		return nil, ErrMissingVerifier
	}

	pae := PAE(e.PayloadType, e.Payload)

	var recognizedVerifiers []Verifier
	for _, sig := range e.Signatures {
		for _, verifier := range v {
			if sig.KeyID != "" && verifier.KeyID() != "" && sig.KeyID != verifier.KeyID() {
				continue
			}
			if verifier.Verify(pae, sig.Signature) == nil {
				recognizedVerifiers = append(recognizedVerifiers, verifier)
			}
		}
	}

	if len(recognizedVerifiers) == 0 {
		return nil, ErrVerification
	}
	return recognizedVerifiers, nil
}
