package dsse

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
)

// Bytes wraps []byte for JSON serialization.
type Bytes []byte

// UnmarshalJSON accepts either standard or URL-safe base64 encodings
func (b *Bytes) UnmarshalJSON(data []byte) error {
	var src string
	if err := json.Unmarshal(data, &src); err != nil {
		return err
	}
	dst, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		if dst, err = base64.URLEncoding.DecodeString(src); err != nil {
			return err
		}
	}
	*b = dst
	return nil
}

// Signature stores a detached signature.
type Signature struct {
	KeyID     string `json:"kid,omitempty"`
	Signature Bytes  `json:"sig"`
}

// Envelope holds the payload and signautres.
// Reference: https://github.com/secure-systems-lab/dsse/blob/master/envelope.md
type Envelope struct {
	Payload     Bytes       `json:"payload"`
	PayloadType string      `json:"payloadType"`
	Signatures  []Signature `json:"signatures"`
}

// PAE encodes the payload type and the payload in the Pre-Authentication Encoding.
// Reference: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#signature-definition
func PAE(payloadType string, payload []byte) []byte {
	pae := []byte("DSSEv1 ")
	pae = strconv.AppendInt(pae, int64(len(payloadType)), 10)
	pae = append(pae, ' ')
	pae = append(pae, payloadType...)
	pae = append(pae, ' ')
	pae = strconv.AppendInt(pae, int64(len(payload)), 10)
	pae = append(pae, ' ')
	pae = append(pae, payload...)
	return pae
}
