package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Constantes
var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)
)

// isPrime verifica se um número é primo usando o teste de primalidade de Miller-Rabin.
func isPrime(n *big.Int) bool {
	return n.ProbablyPrime(20)
}

// generatePrime gera um número primo com exatamente n bits.
func generatePrime(length int) (*big.Int, error) {
	for {
		// Gera um número aleatório com pelo menos n bits
		randomBits := make([]byte, length/8)
		_, err := rand.Read(randomBits)
		if err != nil {
			return nil, err
		}

		// Garante que o número seja ímpar
		randomBits[0] |= 1
		randomBits[len(randomBits)-1] |= 1

		// Cria um big integer a partir dos bytes gerados
		prime := new(big.Int).SetBytes(randomBits)

		// Ajusta para ter exatamente n bits
		prime.SetBit(prime, length-1, 1)

		// Verifica se o número gerado é primo usando o teste de Miller-Rabin
		if isPrime(prime) {
			return prime, nil
		}

		// Imprime um ponto no console a cada segundo
		print(".")
	}
}

// generateGenerator gera um gerador no intervalo [2, p-2]
func generateGenerator(p *big.Int) (*big.Int, error) {
	// Calcula o fator primo seguro q de p
	q := new(big.Int).Rsh(p, 1)

	// Define o limite superior para gerar o gerador
	max := new(big.Int).Sub(p, two)

	for {
		// Escolhe um gerador aleatório g no intervalo [2, p-2]
		g, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, fmt.Errorf("erro ao gerar G: %v", err)
		}

		// Verifica se g^2 mod p != 1 e g^q mod p != 1
		if g.Cmp(two) == 1 && new(big.Int).Exp(g, two, p).Cmp(one) != 0 && new(big.Int).Exp(g, q, p).Cmp(one) != 0 {
			return g, nil
		}
	}
}

// generateElGamalParams gera os parâmetros para o sistema ElGamal
func generateElGamalParams(pSize int) (*big.Int, *big.Int, error) {
	// Gera o número primo P com exatamente pSize bits
	p, err := generatePrime(pSize)
	if err != nil {
		return nil, nil, fmt.Errorf("erro ao gerar P: %v", err)
	}

	// Gera o gerador G no intervalo [2, P-2]
	g, err := generateGenerator(p)
	if err != nil {
		return nil, nil, fmt.Errorf("erro ao gerar G: %v", err)
	}

	return p, g, nil
}

// Função principal
func main() {
	// Definindo o tamanho de P em bits
	pSize := 3072

	// Gerar parâmetros ElGamal
	p, g, err := generateElGamalParams(pSize)
	if err != nil {
		fmt.Println("Erro ao gerar parâmetros ElGamal:", err)
		return
	}

	// Exibe os parâmetros gerados
	fmt.Printf("\nParâmetro P gerado: %s\n", p.String())
	fmt.Printf("Gerador G gerado: %s\n", g.String())
}
