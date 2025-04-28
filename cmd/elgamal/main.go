package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/pedroalbanese/whirlpool"
	"github.com/pedroalbanese/eac/elgamal"
)

// Funções Auxiliares
func loadHexValueFromString(data, label string) (*big.Int, error) {
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, label+" =") {
			hexStr := strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
			bytes, err := hex.DecodeString(hexStr)
			if err != nil {
				return nil, err
			}
			return new(big.Int).SetBytes(bytes), nil
		}
	}
	return nil, fmt.Errorf("rótulo '%s' não encontrado", label)
}

func loadHexValueFromFile(filename, label string) (*big.Int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return loadHexValueFromString(string(data), label)
}

func hashMessage(message []byte) []byte {
	h := whirlpool.New()
	h.Write(message)
	return h.Sum(nil)
}

// Função Principal
func main() {
	keygen := flag.Bool("keygen", false, "Gerar par de chaves ElGamal")
	pubFile := flag.String("pub", "", "Arquivo da chave pública (y)")
	prvFile := flag.String("prv", "", "Arquivo da chave privada (x)")
	decrypt := flag.Bool("decrypt", false, "Modo de descriptografia")
	signFlag := flag.Bool("sign", false, "Modo de assinatura")
	verifyFlag := flag.Bool("verify", false, "Modo de verificação")
	keyFile := flag.String("key", "", "Arquivo da chave (x ou y)")
	signFile := flag.String("signfile", "", "Arquivo de assinatura contendo r e s")
	flag.Parse()

	// Obter parâmetros P e G da biblioteca
	P, G := elgamal.GetParameters()

	// Modo de geração de chaves
	if *keygen {
		if *prvFile == "" || *pubFile == "" {
			log.Fatal("Você deve informar -prv e -pub para salvar as chaves")
		}

		priv, pub, err := elgamal.GenerateKeys()
		if err != nil {
			log.Fatalf("Erro ao gerar chaves: %v", err)
		}

		err = os.WriteFile(*prvFile, []byte(fmt.Sprintf("x = %s\n", hex.EncodeToString(priv.X.Bytes()))), 0600)
		if err != nil {
			log.Fatalf("Erro ao salvar chave privada: %v", err)
		}

		err = os.WriteFile(*pubFile, []byte(fmt.Sprintf("y = %s\n", hex.EncodeToString(pub.Y.Bytes()))), 0644)
		if err != nil {
			log.Fatalf("Erro ao salvar chave pública: %v", err)
		}

		fmt.Println("Par de chaves ElGamal gerado com sucesso.")
		return
	}

	// Verificar modo de operação
	if *keyFile == "" {
		log.Fatal("Você deve especificar um arquivo de chave com -key")
	}

	stdinBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("Erro ao ler stdin: %v", err)
	}

	switch {
	case *decrypt:
		// Modo de descriptografia
		x, err := loadHexValueFromFile(*keyFile, "x")
		if err != nil {
			log.Fatalf("Erro ao carregar chave privada: %v", err)
		}
		priv := &elgamal.PrivateKey{P: P, G: G, X: x}

		c1, err := loadHexValueFromString(string(stdinBytes), "c1")
		if err != nil {
			log.Fatalf("Erro ao ler c1: %v", err)
		}
		c2, err := loadHexValueFromString(string(stdinBytes), "c2")
		if err != nil {
			log.Fatalf("Erro ao ler c2: %v", err)
		}

		msg, err := elgamal.Decrypt(priv, c1, c2)
		if err != nil {
			log.Fatalf("Erro ao descriptografar: %v", err)
		}
		os.Stdout.Write(msg)

	case *signFlag:
		// Modo de assinatura
		x, err := loadHexValueFromFile(*keyFile, "x")
		if err != nil {
			log.Fatalf("Erro ao carregar chave privada: %v", err)
		}
		priv := &elgamal.PrivateKey{P: P, G: G, X: x}

		hash := hashMessage(stdinBytes)
		r, s, err := elgamal.Sign(priv, hash)
		if err != nil {
			log.Fatalf("Erro ao assinar: %v", err)
		}
		
		fmt.Printf("r = %x\ns = %x\n", r, s)

	case *verifyFlag:
		// Modo de verificação
		y, err := loadHexValueFromFile(*keyFile, "y")
		if err != nil {
			log.Fatalf("Erro ao carregar chave pública: %v", err)
		}
		pub := &elgamal.PublicKey{P: P, G: G, Y: y}

		// Ler conteúdo do arquivo de assinatura
		signData, err := os.ReadFile(*signFile)
		if err != nil {
			log.Fatalf("Erro ao ler arquivo de assinatura: %v", err)
		}

		r, err := loadHexValueFromString(string(signData), "r")
		if err != nil {
			log.Fatalf("Erro ao ler r: %v", err)
		}
		s, err := loadHexValueFromString(string(signData), "s")
		if err != nil {
			log.Fatalf("Erro ao ler s: %v", err)
		}

		hash := hashMessage(stdinBytes)
		valid, err := elgamal.Verify(pub, hash, r, s)
		if err != nil {
			log.Fatalf("Erro na verificação: %v", err)
		}

		if valid {
			fmt.Println("✔️ Assinatura válida")
		} else {
			fmt.Println("❌ Assinatura inválida")
		}

	default:
		// Modo de criptografia padrão
		y, err := loadHexValueFromFile(*keyFile, "y")
		if err != nil {
			log.Fatalf("Erro ao carregar chave pública: %v", err)
		}
		pub := &elgamal.PublicKey{P: P, G: G, Y: y}

		c1, c2, err := elgamal.Encrypt(pub, stdinBytes)
		if err != nil {
			log.Fatalf("Erro ao criptografar: %v", err)
		}

		fmt.Printf("c1 = %s\nc2 = %s\n", hex.EncodeToString(c1.Bytes()), hex.EncodeToString(c2.Bytes()))
	}
}
