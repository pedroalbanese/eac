package main

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
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

// Estruturas ASN.1
type Ciphertext struct {
	C1 *big.Int
	C2 *big.Int
}

type Signature struct {
	R *big.Int
	S *big.Int
}

type PublicKeyASN1 struct {
	P *big.Int
	G *big.Int
	Y *big.Int
}

type PrivateKeyASN1 struct {
	P *big.Int
	G *big.Int
	X *big.Int
}

func encodePublicKeyASN1(pub *elgamal.PublicKey) ([]byte, error) {
	return asn1.Marshal(PublicKeyASN1{P: pub.P, G: pub.G, Y: pub.Y})
}

func decodePublicKeyASN1(data []byte) (*elgamal.PublicKey, error) {
	var pubASN1 PublicKeyASN1
	_, err := asn1.Unmarshal(data, &pubASN1)
	if err != nil {
		return nil, err
	}
	return &elgamal.PublicKey{P: pubASN1.P, G: pubASN1.G, Y: pubASN1.Y}, nil
}

func encodePrivateKeyASN1(priv *elgamal.PrivateKey) ([]byte, error) {
	return asn1.Marshal(PrivateKeyASN1{P: priv.P, G: priv.G, X: priv.X})
}

func decodePrivateKeyASN1(data []byte) (*elgamal.PrivateKey, error) {
	var privASN1 PrivateKeyASN1
	_, err := asn1.Unmarshal(data, &privASN1)
	if err != nil {
		return nil, err
	}
	return &elgamal.PrivateKey{P: privASN1.P, G: privASN1.G, X: privASN1.X}, nil
}

func savePEM(filename, blockType string, data []byte) error {
	block := &pem.Block{
		Type:  blockType,
		Bytes: data,
	}
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, block)
}

func readPEM(filename string) ([]byte, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(file)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}
	return block.Bytes, nil
}

func hashMessage(message []byte) []byte {
	h := whirlpool.New()
	h.Write(message)
	return h.Sum(nil)
}

func main() {
	keygen := flag.Bool("keygen", false, "Gerar par de chaves ElGamal")
	pubFile := flag.String("pub", "", "Arquivo da chave pública (PEM)")
	prvFile := flag.String("prv", "", "Arquivo da chave privada (PEM)")
	decrypt := flag.Bool("decrypt", false, "Modo de descriptografia")
	signFlag := flag.Bool("sign", false, "Modo de assinatura")
	verifyFlag := flag.Bool("verify", false, "Modo de verificação")
	keyFile := flag.String("key", "", "Arquivo da chave (PEM)")
	signFile := flag.String("signfile", "", "Arquivo de assinatura (hexadecimal)")
	flag.Parse()

	// Modo de geração de chaves
	if *keygen {
		if *prvFile == "" || *pubFile == "" {
			log.Fatal("Você deve informar -prv e -pub para salvar as chaves")
		}

		priv, pub, err := elgamal.GenerateKeys()
		if err != nil {
			log.Fatalf("Erro ao gerar chaves: %v", err)
		}

		// Salvar chave privada em formato PEM
		privDER, err := encodePrivateKeyASN1(priv)
		if err != nil {
			log.Fatalf("Erro ao codificar chave privada: %v", err)
		}
		err = savePEM(*prvFile, "ELGAMAL PRIVATE KEY", privDER)
		if err != nil {
			log.Fatalf("Erro ao salvar chave privada: %v", err)
		}

		// Salvar chave pública em formato PEM
		pubDER, err := encodePublicKeyASN1(pub)
		if err != nil {
			log.Fatalf("Erro ao codificar chave pública: %v", err)
		}
		err = savePEM(*pubFile, "ELGAMAL PUBLIC KEY", pubDER)
		if err != nil {
			log.Fatalf("Erro ao salvar chave pública: %v", err)
		}

		fmt.Println("Par de chaves ElGamal gerado com sucesso em formato PEM.")
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
		privDER, err := readPEM(*keyFile)
		if err != nil {
			log.Fatalf("Erro ao ler chave privada: %v", err)
		}
		priv, err := decodePrivateKeyASN1(privDER)
		if err != nil {
			log.Fatalf("Erro ao decodificar chave privada: %v", err)
		}

		// Remover espaços em branco e quebras de linha
		hexStr := strings.ReplaceAll(strings.TrimSpace(string(stdinBytes)), "\n", "")
		hexStr = strings.ReplaceAll(hexStr, " ", "")
    
		// Decodificar hexadecimal para DER
		derBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			log.Fatalf("Erro ao decodificar hexadecimal: %v", err)
		}
    
		// Decodificar ciphertext ASN.1 DER
		var cipher Ciphertext
		_, err = asn1.Unmarshal(derBytes, &cipher)
		if err != nil {
			log.Fatalf("Erro ao decodificar ciphertext: %v", err)
		}

		msg, err := elgamal.Decrypt(priv, cipher.C1, cipher.C2)
		if err != nil {
			log.Fatalf("Erro ao descriptografar: %v", err)
		}
		os.Stdout.Write(msg)

	case *signFlag:
		// Modo de assinatura
		privDER, err := readPEM(*keyFile)
		if err != nil {
			log.Fatalf("Erro ao ler chave privada: %v", err)
		}
		priv, err := decodePrivateKeyASN1(privDER)
		if err != nil {
			log.Fatalf("Erro ao decodificar chave privada: %v", err)
		}

		hash := hashMessage(stdinBytes)
		r, s, err := elgamal.Sign(priv, hash)
		if err != nil {
			log.Fatalf("Erro ao assinar: %v", err)
		}

		// Codificar assinatura em ASN.1 DER
		signature := Signature{R: r, S: s}
		sigDER, err := asn1.Marshal(signature)
		if err != nil {
			log.Fatalf("Erro ao codificar assinatura: %v", err)
		}

		// Exibir em hexadecimal
		fmt.Printf("%x\n", sigDER)

	case *verifyFlag:
		// Modo de verificação
		pubDER, err := readPEM(*keyFile)
		if err != nil {
			log.Fatalf("Erro ao ler chave pública: %v", err)
		}
		pub, err := decodePublicKeyASN1(pubDER)
		if err != nil {
			log.Fatalf("Erro ao decodificar chave pública: %v", err)
		}

		// Ler assinatura do arquivo
		sigHex, err := os.ReadFile(*signFile)
		if err != nil {
			log.Fatalf("Erro ao ler arquivo de assinatura: %v", err)
		}

		// Remover espaços em branco e quebras de linha
		hexStr := strings.ReplaceAll(strings.TrimSpace(string(sigHex)), "\n", "")
		hexStr = strings.ReplaceAll(hexStr, " ", "")
    
		// Decodificar hexadecimal para DER
		sigDER, err := hex.DecodeString(string(hexStr))
		if err != nil {
			log.Fatalf("Erro ao decodificar assinatura hexadecimal: %v", err)
		}

		// Decodificar assinatura ASN.1 DER
		var signature Signature
		_, err = asn1.Unmarshal(sigDER, &signature)
		if err != nil {
			log.Fatalf("Erro ao decodificar assinatura: %v", err)
		}

		hash := hashMessage(stdinBytes)
		valid, err := elgamal.Verify(pub, hash, signature.R, signature.S)
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
		pubDER, err := readPEM(*keyFile)
		if err != nil {
			log.Fatalf("Erro ao ler chave pública: %v", err)
		}
		pub, err := decodePublicKeyASN1(pubDER)
		if err != nil {
			log.Fatalf("Erro ao decodificar chave pública: %v", err)
		}

		c1, c2, err := elgamal.Encrypt(pub, stdinBytes)
		if err != nil {
			log.Fatalf("Erro ao criptografar: %v", err)
		}

		// Codificar ciphertext em ASN.1 DER
		cipher := Ciphertext{C1: c1, C2: c2}
		cipherDER, err := asn1.Marshal(cipher)
		if err != nil {
			log.Fatalf("Erro ao codificar ciphertext: %v", err)
		}

		// Exibir em hexadecimal
		fmt.Printf("%x\n", cipherDER)
	}
}
