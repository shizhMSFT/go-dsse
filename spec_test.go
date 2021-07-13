package dsse

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"testing"
)

func TestBytesUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
		want    []byte
		wantErr bool
	}{
		{
			name:    "standard encoding",
			encoded: `"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"`,
			want: []byte{
				0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92,
				0x8b, 0x30, 0xd3, 0x8f, 0x41, 0x14, 0x93, 0x51,
				0x55, 0x97, 0x61, 0x96, 0x9b, 0x71, 0xd7, 0x9f,
				0x82, 0x18, 0xa3, 0x92, 0x59, 0xa7, 0xa2, 0x9a,
				0xab, 0xb2, 0xdb, 0xaf, 0xc3, 0x1c, 0xb3, 0xd3,
				0x5d, 0xb7, 0xe3, 0x9e, 0xbb, 0xf3, 0xdf, 0xbf,
			},
		},
		{
			name:    "url encoding",
			encoded: `"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"`,
			want: []byte{
				0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92,
				0x8b, 0x30, 0xd3, 0x8f, 0x41, 0x14, 0x93, 0x51,
				0x55, 0x97, 0x61, 0x96, 0x9b, 0x71, 0xd7, 0x9f,
				0x82, 0x18, 0xa3, 0x92, 0x59, 0xa7, 0xa2, 0x9a,
				0xab, 0xb2, 0xdb, 0xaf, 0xc3, 0x1c, 0xb3, 0xd3,
				0x5d, 0xb7, 0xe3, 0x9e, 0xbb, 0xf3, 0xdf, 0xbf,
			},
		},
		{
			name:    "bad encoding",
			encoded: `"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,"`,
			wantErr: true,
		},
		{
			name:    "raw encoding",
			encoded: `"aGVsbG8gd29ybGQ"`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Bytes
			if err := json.Unmarshal([]byte(tt.encoded), &b); (err != nil) != tt.wantErr {
				t.Errorf("Bytes.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !bytes.Equal(b, tt.want) {
				t.Errorf("Bytes.UnmarshalJSON() = %v, want %v", b, tt.want)
			}
		})
	}
}

func TestPAE(t *testing.T) {
	tests := []struct {
		name        string
		payloadType string
		payload     []byte
		want        []byte
	}{
		{
			name:        "nil payload",
			payloadType: "",
			payload:     nil,
			want:        []byte("DSSEv1 0  0 "),
		},
		{
			name:        "empty payload",
			payloadType: "",
			payload:     []byte{},
			want:        []byte("DSSEv1 0  0 "),
		},
		{
			name:        "standard test case",
			payloadType: "http://example.com/HelloWorld",
			payload:     []byte("hello world"),
			want:        []byte("DSSEv1 29 http://example.com/HelloWorld 11 hello world"),
		},
		{
			name:        "binary payload",
			payloadType: "binary",
			payload:     []byte{0xff, 0x00, 0xff, 0x00},
			want:        append([]byte("DSSEv1 6 binary 4 "), 0xff, 0x00, 0xff, 0x00),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PAE(tt.payloadType, tt.payload); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PAE() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkPAE_128(b *testing.B) {
	benchmarkPAE(b, 128)
}

func BenchmarkPAE_512(b *testing.B) {
	benchmarkPAE(b, 512)
}

func BenchmarkPAE_2K(b *testing.B) {
	benchmarkPAE(b, 2048)
}

func BenchmarkPAE_4K(b *testing.B) {
	benchmarkPAE(b, 4096)
}
func benchmarkPAE(b *testing.B, size int64) {
	payloadType := fmt.Sprintf("application/vnd.payload.%d", size)
	payload, err := io.ReadAll(io.LimitReader(rand.Reader, size))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PAE(payloadType, payload)
	}
}
