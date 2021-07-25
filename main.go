package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const (
	KeySize = 2048
)

func GenerateKeypair(keySize int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func Hash(data []byte) ([]byte, error) {
	msgHash := sha256.New()
	_, err := msgHash.Write(data)
	if err != nil {
		return nil, err
	}
	return msgHash.Sum(nil), nil
}

func Base64Encode(message []byte) []byte {
	b := make([]byte, base64.StdEncoding.EncodedLen(len(message)))
	base64.StdEncoding.Encode(b, message)
	return b
}

func Base64Decode(message []byte) (b []byte, err error) {
	var l int
	b = make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	l, err = base64.StdEncoding.Decode(b, message)
	if err != nil {
		return
	}
	return b[:l], nil
}

func main() {
	privateKey, publicKey, err := GenerateKeypair(KeySize)
	if err != nil {
		panic(err)
	}
	fmt.Println("Private Key: ", privateKey)
	fmt.Println("Public key: ", publicKey)
	fmt.Println("Keypair generation complete!\n")

	msg := []byte("Это сообщение для проверки подписи")
	fmt.Printf("msg: %s\n", msg)

	msgHash, err := Hash(msg)
	if err != nil {
		panic(err)
	}
	fmt.Printf("msgHash: %x\n", msgHash)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHash, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature in base64: %s\n", Base64Encode(signature))

	err = rsa.VerifyPSS(publicKey, crypto.SHA256, msgHash, signature, nil)
	if err != nil {
		fmt.Println("Could not verify signature: ", err)
		return
	}
	// Подпись верна, если функция VerifyPSS не вернула ошибок
	fmt.Println("Signature verified\n")

	// Пробуем проверить, действительна ли подпись уже для другого сообщения:
	newMsg := []byte("Это уже совсем другое сообщение")
	fmt.Printf("newMsg: %s\n", newMsg)

	newMsgHash, err := Hash(newMsg)
	if err != nil {
		panic(err)
	}
	fmt.Printf("newMsgHash: %x\n", newMsgHash)

	err = rsa.VerifyPSS(publicKey, crypto.SHA256, newMsgHash, signature, nil)
	if err != nil {
		fmt.Println("Could not verify signature: ", err)
		return
	}

	fmt.Println("Signature verified")
}
