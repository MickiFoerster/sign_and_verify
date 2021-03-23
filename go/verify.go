package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("syntax error: %v '<message to sign>'\n", path.Base(os.Args[0]))
		os.Exit(1)
	}
	msg := os.Args[1]
	hash := sha256.Sum256([]byte(msg))

	sig, err := ioutil.ReadFile("signature.bin")
	if err != nil {
		log.Fatalf("error: could not read signature: %v\n", err)
	}

	x, err := ioutil.ReadFile("X.key")
	if err != nil {
		log.Fatalf("error: could not read public key X from file")
	}
	y, err := ioutil.ReadFile("Y.key")
	if err != nil {
		log.Fatalf("error: could not read public key Y from file")
	}

	pubkey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}

	valid := ecdsa.VerifyASN1(&pubkey, hash[:], sig)
	if valid {
		fmt.Println("Signature is valid.")
	} else {
		fmt.Println("Signature is invalid!")
	}
}
