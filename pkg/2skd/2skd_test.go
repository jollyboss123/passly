package _2skd

import (
	"reflect"
	"testing"
)

func Test2KSDFlow(t *testing.T) {
	masterPass := []byte("master")
	plain := []byte("plain")

	// generate secret key
	sk, err := GenSecretKey(31)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := Encrypter(masterPass, plain, sk) // save ciphertext for decryption
	if err != nil {
		t.Fatal(err)
	}

	result, err := Decrypter(masterPass, ciphertext, sk)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(plain, result) {
		t.Errorf("want %x, got %x", string(plain), string(result))
	}
}
