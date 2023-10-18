package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/jollyboss123/passly/pkg/pbkdf2"
	"github.com/jollyboss123/passly/pkg/pkcs7"
	"io"

	"log"
	"math/big"
)

func main() {
	masterPass := []byte("password")
	log.Println("pw: ", string(masterPass))

	ciphertext, err := encrypter(masterPass)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ciphertext: %x\n", ciphertext)

}

func encrypter(password []byte) ([]byte, error) {
	// generate secret key
	sk, err := genSecretKey(31)
	if err != nil {
		return nil, err
	}
	log.Println("secret: ", string(sk))

	// generate pbkdf2 key
	key := pbkdf2.Key(password, sk, 100_000, 256/8, sha512.New)
	result := ""
	for _, k := range key {
		result += fmt.Sprintf("%02X", k)
	}
	log.Println("key: ", result)

	// pad password to aes block size
	password, err = pkcs7.Pad(password, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	log.Println("padded: ", string(password))

	// make cipher text
	ciphertext := make([]byte, aes.BlockSize+len(password))

	// make iv and prepend to the cipher text
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	resIV := ""
	for _, i := range iv {
		resIV += fmt.Sprintf("%02x", i)
	}
	log.Println("iv: ", resIV)

	// make new aes cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// encrypt with cbc
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], password)
	return ciphertext, nil
}

// genSecretKey generates secret key to be store at client side
// TODO: maybe should just do in mobile?
func genSecretKey(keyLen int) ([]byte, error) {
	key := make([]byte, keyLen)
	const char = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	for k := range key {
		random, err := rand.Int(rand.Reader, big.NewInt(int64(len(char))))
		if err != nil {
			return nil, err
		}
		key[k] = char[random.Int64()]
	}
	return key, nil
}
