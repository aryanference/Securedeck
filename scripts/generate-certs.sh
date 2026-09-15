#!/bin/sh
set -e

mkdir -p certs

# Simple script to generate some key material for testing (not actual mTLS right now just the ed25519 signing key)
# For the broker signing key we need an Ed25519 private key in PEM format.
# We will create a small go program to generate it if it doesn't exist.

cat << 'EOF' > certs/gen.go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	privBlock := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv,
	}
	os.WriteFile("certs/broker.key", pem.EncodeToMemory(privBlock), 0600)

	pubBlock := &pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: pub,
	}
	os.WriteFile("certs/broker.pub", pem.EncodeToMemory(pubBlock), 0644)
}
EOF

go run certs/gen.go
rm certs/gen.go

echo "Generated keys in certs/ directory"
