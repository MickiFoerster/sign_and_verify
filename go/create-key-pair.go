package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io/ioutil"
	"log"
)

func main() {
	keypair, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("error: could not create key pair: %v\n", err)
	}

	if err := ioutil.WriteFile("D.key", keypair.D.Bytes(), 0600); err != nil {
		log.Fatalf("error: could not write private key D to file: %v\n", err)
	}
	if err := ioutil.WriteFile("X.key", keypair.X.Bytes(), 0600); err != nil {
		log.Fatalf("error: could not write public key X to file: %v\n", err)
	}
	if err := ioutil.WriteFile("Y.key", keypair.Y.Bytes(), 0600); err != nil {
		log.Fatalf("error: could not write public key Y to file: %v\n", err)
	}
}
