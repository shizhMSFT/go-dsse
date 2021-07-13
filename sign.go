package dsse

// Signer signs messages.
type Signer interface {
	// Sign returns the signature of the `message`.
	Sign(message []byte) ([]byte, error)

	// KeyID returns the key ID of the signing key.
	// Empty if not supported.
	KeyID() string
}

// EnvelopeSigner is a group of signers.
type EnvelopeSigner []Signer

// NewEnvelopeSigner wraps signers to be an envelope signer.
func NewEnvelopeSigner(signers ...Signer) EnvelopeSigner {
	return signers
}

// Sign signs the payload with its type.
// Reference: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#protocol
func (s EnvelopeSigner) Sign(payloadType string, payload []byte) (*Envelope, error) {
	if len(s) == 0 {
		return nil, ErrMissingSigner
	}

	e := &Envelope{
		Payload:     append([]byte{}, payload...),
		PayloadType: payloadType,
	}
	pae := PAE(e.PayloadType, e.Payload)
	for _, signer := range s {
		sig, err := signer.Sign(pae)
		if err != nil {
			return nil, err
		}
		e.Signatures = append(e.Signatures, Signature{
			KeyID:     signer.KeyID(),
			Signature: sig,
		})
	}

	return e, nil
}
