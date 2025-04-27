package main

import (
	"crypto/rand"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/pedroalbanese/eac"
)

func main() {
	// Flags da aplicação
	keyHex := flag.String("key", "", "Chave hexadecimal (128-bit para Anubis)")
	aad := flag.String("aad", "", "Dados adicionais autenticados (string)")
	decryptFlag := flag.Bool("decrypt", false, "Modo de descriptografia")
	flag.Parse()

	// Validar chave
	if *keyHex == "" {
		log.Fatal("Erro: chave não fornecida (use -key)")
	}

	key, err := hex.DecodeString(*keyHex)
	if err != nil {
		log.Fatalf("Erro ao decodificar chave: %v", err)
	}

	// Validar tamanho da chave (128-bit para Anubis)
	if len(key) != 16 {
		log.Fatal("Erro: chave deve ter 16 bytes (128 bits)")
	}

	// Ler dados de entrada (stdin)
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("Erro ao ler entrada: %v", err)
	}

	// Instanciar EAC
	aead, err := eac.NewEAC(key)
	if err != nil {
		log.Fatalf("Erro ao criar AEAD: %v", err)
	}

	if *decryptFlag {
		// Modo descriptografia
		decrypted, err := decrypt(aead, input, []byte(*aad))
		if err != nil {
			log.Fatalf("Erro na descriptografia: %v", err)
		}
		fmt.Print(string(decrypted))
	} else {
		// Modo criptografia
		encrypted, err := encrypt(aead, input, []byte(*aad))
		if err != nil {
			log.Fatalf("Erro na criptografia: %v", err)
		}
		fmt.Println(hex.EncodeToString(encrypted))
	}
}

func encrypt(aead cipher.AEAD, plaintext, aad []byte) ([]byte, error) {
	// Gerar nonce aleatório
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("erro ao gerar nonce: %w", err)
	}

	// Prefix bit zero como no EAX
	nonce[0] &= 0x7F

	// Criptografar: nonce | ciphertext | tag
	ciphertext := aead.Seal(nonce, nonce, plaintext, aad)
	return ciphertext, nil
}

func decrypt(aead cipher.AEAD, ciphertext, aad []byte) ([]byte, error) {
	// Decodificar se estiver em hexadecimal
	if isHex(ciphertext) {
		var err error
		ciphertext, err = hex.DecodeString(string(ciphertext))
		if err != nil {
			return nil, fmt.Errorf("erro ao decodificar hex: %w", err)
		}
	}

	// Verificar tamanho mínimo
	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("dados criptografados muito curtos")
	}

	// Separar nonce e ciphertext+tag
	nonce := ciphertext[:aead.NonceSize()]
	actualCiphertext := ciphertext[aead.NonceSize():]

	// Descriptografar
	plaintext, err := aead.Open(nil, nonce, actualCiphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("falha na autenticação/descriptografia: %w", err)
	}

	return plaintext, nil
}

func isHex(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Verifica se todos os caracteres são hexadecimais
	for _, b := range data {
		if !((b >= '0' && b <= '9') || 
		     (b >= 'a' && b <= 'f') || 
		     (b >= 'A' && b <= 'F') ||
		     b == '\n' || b == ' ') {
			return false
		}
	}
	return true
}
