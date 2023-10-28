package main

func main() {
	//masterPass := []byte("master")
	//plain := []byte("plain")
	//log.Println("pw: ", string(masterPass))
	//
	//// generate secret key
	//sk, err := genSecretKey(31)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//log.Println("secret: ", string(sk))
	//
	//ciphertext, err := encrypter(masterPass, plain, sk) // save ciphertext for decryption
	//if err != nil {
	//	log.Fatal(err)
	//}
	//log.Printf("ciphertext: %x\n", ciphertext)
	//
	//result, err := decrypter(masterPass, ciphertext, sk)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//log.Println("decrypted: ", string(result))
}

//export generateSecretKey
//func generateSecretKey(keyLen *C.int) (*C.char, *C.char) {
//	key, err := genSecretKey(C.GoInt(keyLen))
//	if err != nil {
//		return nil, C.CString(err.Error())
//	}
//	return C.CString(key), nil
//}
