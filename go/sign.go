package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	d, err := ioutil.ReadFile("D.key")
	if err != nil {
		log.Fatalf("error: could not read private key D from file")
	}
	privkey := ecdsa.PrivateKey{
		PublicKey: pubkey,
		D:         new(big.Int).SetBytes(d),
	}

	sig, err := ecdsa.SignASN1(rand.Reader, &privkey, hash[:])
	if err != nil {
		log.Fatalf("error: could not create signature: %v\n", err)
	}

	if err := ioutil.WriteFile("signature.bin", sig, 0600); err != nil {
		log.Fatalf("error: could not write signature to file: %v\n", err)
	}
}
