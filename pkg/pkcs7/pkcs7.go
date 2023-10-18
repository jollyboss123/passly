package pkcs7

import (
	"bytes"
	"fmt"
)

// Pad appends padding
func Pad(data []byte, blockLen int) ([]byte, error) {
	if blockLen <= 0 {
		return nil, fmt.Errorf("invalid blockLen: %d", blockLen)
	}
	padLen := 1
	for ((len(data) + padLen) % blockLen) != 0 {
		padLen = padLen + 1
	}

	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, pad...), nil
}

// Unpad returns slice of original data without padding
func Unpad(data []byte, blockLen int) ([]byte, error) {
	if blockLen <= 0 {
		return nil, fmt.Errorf("invalid blockLen: %d", blockLen)
	}
	if len(data)%blockLen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len: %d", len(data))
	}
	padLen := int(data[len(data)-1])
	if padLen > blockLen || padLen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	pad := data[len(data)-padLen:]
	for i := 0; i < padLen; i++ {
		if pad[i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padLen], nil
}
