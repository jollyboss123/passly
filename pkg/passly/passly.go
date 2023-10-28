package passly

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

func Encrypter(password, plain, secretKey []byte) (ciphertext []byte, err error) {
	// generate pbkdf2 key from password and secret key
	key := pbkdf2.Key(password, secretKey, 650_000, 256/8, sha512.New)
	result := ""
	for _, k := range key {
		result += fmt.Sprintf("%02X", k)
	}
	log.Println("key: ", result)

	// pad password to aes block size
	plain, err = pkcs7.Pad(plain, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	log.Println("padded: ", string(plain))

	// make cipher text
	ciphertext = make([]byte, aes.BlockSize+len(plain))

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

	// make new aes cipher from password, key and iv
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// encrypt with cbc
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plain)
	return ciphertext, nil
}

func Decrypter(password, ciphertext, secretKey []byte) ([]byte, error) {
	key := pbkdf2.Key(password, secretKey, 650_000, 256/8, sha512.New)
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
func GenSecretKey(keyLen int) ([]byte, error) {
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
