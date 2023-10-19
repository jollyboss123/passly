package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"github.com/jollyboss123/passly/pkg/pbkdf2"
	"github.com/jollyboss123/passly/pkg/pkcs7"
	"io"

	"log"
	"math/big"
)

func main() {
	masterPass := []byte("password")
	plain := []byte("plain")
	log.Println("pw: ", string(masterPass))

	// generate secret key
	sk, err := genSecretKey(31)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("secret: ", string(sk))

	ciphertext, _, err := encrypter(masterPass, plain, sk) // save ciphertext and iv for decryption
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ciphertext: %x\n", ciphertext)

	result, err := decrypter(masterPass, ciphertext, sk)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("decrypted: ", string(result))
}

func encrypter(password, plain, secretKey []byte) (ciphertext []byte, iv []byte, err error) {
	// generate pbkdf2 key from password and secret key
	key := pbkdf2.Key(password, secretKey, 100_000, 256/8, sha512.New)
	result := ""
	for _, k := range key {
		result += fmt.Sprintf("%02X", k)
	}
	log.Println("key: ", result)

	// pad password to aes block size
	plain, err = pkcs7.Pad(plain, aes.BlockSize)
	if err != nil {
		return nil, nil, err
	}
	log.Println("padded: ", string(plain))

	// make cipher text
	ciphertext = make([]byte, aes.BlockSize+len(plain))

	// make iv and prepend to the cipher text
	iv = ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}
	resIV := ""
	for _, i := range iv {
		resIV += fmt.Sprintf("%02x", i)
	}
	log.Println("iv: ", resIV)

	// make new aes cipher from password, key and iv
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// encrypt with cbc
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plain)
	return ciphertext, iv, nil
}

func decrypter(password, ciphertext, secretKey []byte) ([]byte, error) {
	key := pbkdf2.Key(password, secretKey, 100_000, 256/8, sha512.New)
	result := ""
	for _, k := range key {
		result += fmt.Sprintf("%02X", k)
	}
	log.Println("key: ", result)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	log.Printf("iv: %x\n", iv)

	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
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
