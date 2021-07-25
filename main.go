package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
)

const (
	KeySize = 2048
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
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

func check(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	msg := []byte(r.Form.Get("message"))
	b64sign := []byte(r.Form.Get("signature"))
	fmt.Fprintf(w, "Message: %s\n", msg)
	fmt.Fprintf(w, "Signature: %s\n", b64sign)
	signature, err := Base64Decode(b64sign)
	if err != nil {
		fmt.Fprintln(w, "Wrong sign format: ", err)
		return
	}
	msgHash, err := Hash(msg)
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}
	fmt.Fprintf(w, "Hash: %x\n", msgHash)
	err = rsa.VerifyPSS(publicKey, crypto.SHA256, msgHash, signature, nil)
	if err != nil {
		fmt.Fprintln(w, "Could not verify signature: ", err)
		return
	}
	fmt.Fprintln(w, "Signature verified")
}

func signed(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	msg := []byte(r.Form.Get("message"))
	fmt.Fprintf(w, "Message: %s\n", msg)
	msgHash, err := Hash(msg)
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}
	fmt.Fprintf(w, "Hash: %x\n", msgHash)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHash, nil)
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}
	fmt.Fprintf(w, "Signature in base64: %s\n", Base64Encode(signature))
}

func main() {
	var err error
	privateKey, publicKey, err = GenerateKeypair(KeySize)
	if err != nil {
		panic(err)
	}
	fmt.Println("Keypair generation complete!\n")

	// index := http.FileServer(http.Dir("./static/index/"))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/index/index.html")
	})
	// sign := http.FileServer(http.Dir("./static/sign/"))
	// http.Handle("/", index)
	http.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/sign/sign.html")
	})
	http.HandleFunc("/check", check)
	http.HandleFunc("/signed", signed)
	fmt.Println("Listening on :80")
	err = http.ListenAndServe(":80", nil)
	if err != nil {
		panic(err)
	}
}
