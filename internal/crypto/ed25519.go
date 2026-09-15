package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
)

func GenerateKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, pub, err
}

func Sign(priv ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(priv, message)
}

func Verify(pub ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(pub, message, signature)
}

func PrivateKeyToPEM(priv ed25519.PrivateKey) []byte {
	block := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv,
	}
	return pem.EncodeToMemory(block)
}

func PublicKeyToPEM(pub ed25519.PublicKey) []byte {
	block := &pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: pub,
	}
	return pem.EncodeToMemory(block)
}

func PEMToPrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block")
	}
	return ed25519.PrivateKey(block.Bytes), nil
}

func PEMToPublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "ED25519 PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM block")
	}
	return ed25519.PublicKey(block.Bytes), nil
}
