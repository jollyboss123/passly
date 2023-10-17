package main

import (
	"crypto/rand"
	"fmt"
	"github.com/jollyboss123/passly/pkg/pbkdf2"

	"log"
	"math/big"
)

func main() {
	masterPass := []byte("password")
	log.Println("pw: " + string(masterPass))
	sk := genSecretKey(31)
	log.Println("secret: " + string(sk))
	key := pbkdf2.Key(masterPass, sk, 100_000, 256/8)
	result := ""
	for _, k := range key {
		result += fmt.Sprintf("%02X", k)
	}
	log.Println("key: " + result)
}

// genSecretKey generates secret key to be store at client side
// TODO: maybe should just do in mobile?
func genSecretKey(n int) []byte {
	key := make([]byte, n)
	const char = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	for k := range key {
		random, err := rand.Int(rand.Reader, big.NewInt(int64(len(char))))
		if err != nil {
			return nil
		}
		key[k] = char[random.Int64()]
	}
	return key
}
