package main

import (
	"encoding/hex"
	"fmt"
	"log"
	
	"github.com/pedroalbanese/eac"
)

func main() {
	// Chave hard-coded (128-bit Anubis)
	key, err := hex.DecodeString("00000000000000000000000000000000")
	if err != nil {
		log.Fatalf("hex decode key: %v", err)
	}
	
	// Dados hard-coded
	head := []byte("cabecalho")
	plaintext := []byte("mensagem secreta com eac")

	// Instancia AEAD
	aead, err := eac.NewEAC(key)

	if err != nil {
		log.Fatalf("new AEAD: %v", err)
	}

	// 1) Encrypt: Seal(dst, nonce, plaintext, associatedData)
	nonce := make([]byte, 12)
	
	// Prefix bit zero como no EAX
	nonce[0] &= 0x7F

	out := aead.Seal(nonce, nonce, plaintext, head)

	// Print hex: nonce | ciphertext | tag
	fmt.Println(hex.EncodeToString(out))

	// 2) Decrypt: separa nonce e ciphertext+tag
	nonce2 := out[:aead.NonceSize()]
	ciphertext := out[aead.NonceSize():]

	pt, err := aead.Open(nil, nonce2, ciphertext, head)
	if err != nil {
		log.Fatalf("open: %v", err)
	}

	fmt.Println(string(pt))
}
