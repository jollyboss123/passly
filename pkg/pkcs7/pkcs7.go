package pkcs7

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
)

var (
	errInvalidPadding  = errors.New("invalid padding")
	errInvalidBlockLen = errors.New("invalid block len")
	errInvalidDataLen  = errors.New("invalid data len")
)

// Pad appends padding to the given buffer such that the resulting slice
// of bytes has a length divisible by the given size. If you are using this
// function to pad a plaintext before encrypting it with a block cipher, the
// size should be equal to the block size of the cipher (e.g., aes.BlockSize).
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

// Unpad returns slice of original data without padding.
// It checks the correctness of the padding bytes in constant time, and
// returns an error if the padding bytes are malformed.
func Unpad(data []byte, blockLen int) ([]byte, error) {
	if blockLen <= 0 {
		return nil, errInvalidBlockLen
	}
	if len(data)%blockLen != 0 || len(data) == 0 {
		return nil, errInvalidDataLen
	}
	padLen := int(data[len(data)-1])
	if padLen > blockLen || padLen == 0 {
		return nil, errInvalidPadding
	}

	valid := 1
	pad := data[len(data)-padLen:]
	for i := 0; i < padLen; i++ {
		b := pad[i]
		outOfRange := subtle.ConstantTimeLessOrEq(padLen, i)
		equal := subtle.ConstantTimeByteEq(byte(padLen), b)
		valid &= subtle.ConstantTimeSelect(outOfRange, 1, equal)
	}

	valid &= subtle.ConstantTimeLessOrEq(1, padLen)
	valid &= subtle.ConstantTimeLessOrEq(padLen, len(data))

	if valid != 1 {
		return nil, errInvalidPadding
	}

	return data[:len(data)-padLen], nil
}
