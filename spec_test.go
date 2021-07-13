package dsse

import (
	"crypto/rand"
	"fmt"
	"io"
	"reflect"
	"testing"
)

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
	for i := 0; i < b.N; i++ {
		PAE(payloadType, payload)
	}
}
