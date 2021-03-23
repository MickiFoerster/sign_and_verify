# sign_and_verify with ECDSA cryptography

This repository contains tools for signing and verifying files with elliptic
curve cryptograpy. 

- C contains C implementation with mbedtls
- go contains implementation with standard ecdsa library 


## Build

Execute the following to build the project:
```
sudo apt install wget cmake ninja-build gcc make
make
```

## Create keypair
To use this you create first a public and private key:

```
./ecdsa-keygen
```

This creates the files `key.priv` (private key) and `key.pub` (public key).
Keep the private key secret. You only need it for creating the signature.
The verification only needs the public key and it will be stored together
with the signature into a file with extension `.sig`.

## Create Signature
```
./ecdsa-sign mydocument.doc
```

This creates a  file `mydocument.doc.sig`.

## Verify Signature

Provide the files `mydocument.doc` and its signature `mydocument.doc.sig`
to Bob. Then Bob can verify your signature by using:
```
./ecdsa-verify mydocument.doc.sig
Signature is valid!
```
