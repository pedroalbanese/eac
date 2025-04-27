package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"os"

	"github.com/pedroalbanese/eac"
	"github.com/pedroalbanese/whirlpool"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

func main() {
	// Flags da aplicação
	keyHex := flag.String("key", "", "Chave/senha (hex ou texto)")
	aad := flag.String("aad", "", "Dados adicionais autenticados (string)")
	decryptFlag := flag.Bool("decrypt", false, "Modo de descriptografia")
	pbkdf2Flag := flag.Bool("pbkdf2", false, "Usar PBKDF2 para derivar chave")
	hmacFlag := flag.Bool("hmac", false, "Calcular HMAC-Whirlpool")
	hkdfFlag := flag.Bool("hkdf", false, "Usar HKDF para derivar chave")
	salt := flag.String("salt", "", "Salt para derivação de chaves")
	iter := flag.Int("iter", 100000, "Iterações para PBKDF2")
	bits := flag.Int("bits", 256, "Tamanho da chave derivada em bits")
	randFlag := flag.Bool("rand", false, "Gerar chave aleatória")
	flag.Parse()

	// Modo gerar chave aleatória
	if *randFlag {
		key := make([]byte, *bits/8)
		if _, err := rand.Read(key); err != nil {
			log.Fatalf("Erro ao gerar chave aleatória: %v", err)
		}

		fmt.Println("=== Chave Aleatória ===")
		fmt.Printf("Hex: %x\n", key)
		return
	}
	
	// Validar combinações de flags
	if *pbkdf2Flag && *hkdfFlag {
		log.Fatal("Erro: use apenas PBKDF2 ou HKDF, não ambos")
	}

	keyBits := *bits

	derivedKeySize := keyBits / 8

	var key []byte
	// Modo HKDF (independente)
	if *hkdfFlag {
		if *keyHex == "" {
			log.Fatal("Erro: chave não fornecida para HKDF (use -key)")
		}

		hkdf := hkdf.New(func() hash.Hash {
			return whirlpool.New()
		}, []byte(*keyHex), []byte(*salt), []byte(*aad))

		okm := make([]byte, derivedKeySize)
		if _, err := io.ReadFull(hkdf, okm); err != nil {
			log.Fatalf("Erro ao derivar chave com HKDF: %v", err)
		}

		fmt.Println("=== HKDF-Whirlpool ===")
		fmt.Printf("IKM (Input Key Material): %s\n", *keyHex)
		fmt.Printf("Salt: %s\n", *salt)
		fmt.Printf("Info: %s\n", *aad)
		fmt.Printf("OKM (Output Key Material, %d bits):\n%x\n", keyBits, okm)
		return
	}

	// Ler dados de entrada (stdin)
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("Erro ao ler entrada: %v", err)
	}

	if *hmacFlag {
		// Modo HMAC
		if *keyHex == "" {
			log.Fatal("Erro: chave não fornecida para HMAC (use -key)")
		}

		mac := hmacWhirlpool(input, []byte(*keyHex))
		fmt.Println(hex.EncodeToString(mac))
		return
	}

	// Modos de criptografia/descriptografia
	if *keyHex == "" {
		log.Fatal("Erro: chave não fornecida (use -key)")
	}

	// Modos de criptografia/descriptografia (não HKDF)
	if *keyHex == "" {
		log.Fatal("Erro: chave não fornecida (use -key)")
	}

	if *pbkdf2Flag {
		// Derivação de chave com PBKDF2
		password := []byte(*keyHex)
		key = pbkdf2.Key(password, []byte(*salt), *iter, derivedKeySize, func() hash.Hash {
			return whirlpool.New()
		})
		fmt.Fprintf(os.Stderr, "Salt usado: %s\n", []byte(*salt))
		fmt.Fprintf(os.Stderr, "Iterações: %d\n", *iter)
		fmt.Fprintf(os.Stderr, "Tamanho da chave: %d bits\n", keyBits)
	} else {
		// Chave direta (hex)
		if isHex([]byte(*keyHex)) {
			key, err = hex.DecodeString(*keyHex)
			if err != nil {
				log.Fatalf("Erro ao decodificar chave: %v", err)
			}
		} else {
			key = []byte(*keyHex)
		}
	}

	// Validar tamanho da chave para Anubis (128 bits)
	if len(key) < 16 || len(key) > 40 {
		log.Fatal("Erro: chave deve ter pelo menos 16 bytes (128 bits)")
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

func hmacWhirlpool(message, key []byte) []byte {
	// Tamanho do blho Whirlpool (64 bytes)
	const blockSize = 64

	// Reduzir chave se for muito grande
	if len(key) > blockSize {
		hasher := whirlpool.New()
		hasher.Write(key)
		key = hasher.Sum(nil)
	}

	// Preencher chave se for muito pequena
	if len(key) < blockSize {
		paddedKey := make([]byte, blockSize)
		copy(paddedKey, key)
		key = paddedKey
	}

	// Padrões HMAC
	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5c
	}

	// Primeiro hash (inner)
	inner := whirlpool.New()
	inner.Write(ipad)
	inner.Write(message)
	innerHash := inner.Sum(nil)

	// Segundo hash (outer)
	outer := whirlpool.New()
	outer.Write(opad)
	outer.Write(innerHash)

	return outer.Sum(nil)
}

func encrypt(aead cipher.AEAD, plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("erro ao gerar nonce: %w", err)
	}
	nonce[0] &= 0x7F // Ajuste EAX

	ciphertext := aead.Seal(nonce, nonce, plaintext, aad)
	return ciphertext, nil
}

func decrypt(aead cipher.AEAD, ciphertext, aad []byte) ([]byte, error) {
	if isHex(ciphertext) {
		var err error
		ciphertext, err = hex.DecodeString(string(ciphertext))
		if err != nil {
			return nil, fmt.Errorf("erro ao decodificar hex: %w", err)
		}
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("dados criptografados muito curtos")
	}

	nonce := ciphertext[:aead.NonceSize()]
	actualCiphertext := ciphertext[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, actualCiphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("falha na autenticação/descriptografia: %w", err)
	}

	return plaintext, nil
}

func isHex(data []byte) bool {
	for _, b := range data {
		if !((b >= '0' && b <= '9') || 
		     (b >= 'a' && b <= 'f') || 
		     (b >= 'A' && b <= 'F') ||
		     b == '\n' || b == ' ') {
			return false
		}
	}
	return len(data) > 0
}
