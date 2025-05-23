package elgamal

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// Constantes
var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)
)

// Estruturas de Chave
type PrivateKey struct {
	P, G, X *big.Int
}

type PublicKey struct {
	P, G, Y *big.Int
}

// Parâmetros fixos (3072 bits)
var (
	p, _ = new(big.Int).SetString("b3361eb41e256582262a39a8bd0e093a434fe64ab005da3cd65880ea1d8ddd2568ff508e05f3a3fe5358eeb06a32329cf211cd6db30f61bfea323e2ca06fd3fdedcb79045a9b6506090d3dd2cd31148ccaa92cf95273490cdbcf285ec6ccb6ae4607a0654a518ecf21897a0e92e2caade5a66d90dd8c6775717f126413fee527a7ecfdc870cc74438a71cfddb486aadb9b74a4c09f1d2d20c5ca7a5a73526782ccc51d868f97485a8eec21ed20ad20590d3999a472dcfddb3f77f3c3315e7aea64372092f0e93161a82397e3592e275697efced77683584ccb7a01fdc83117d5f28cb818fafaa2abb2284562f92e45902c50cef61c2547eb31d7afaa50485b0229b9a7ad803d473ddc66218ebf1c284dc2fdc251caa7a77299081f12d8ca91f63200e29812b7a09a229f3c05a0037df4478f9146a334a89bf49a716cee243f7f7cfc08ba485d2a420a7361a21aa115773f555cedd7b39ed48e70ae8c7887903a1f9fd386ce0648e34c7e6054943fceadf0efdcec6b7f9d5f6f4473e7d8ab5c6f", 16)
	g, _ = new(big.Int).SetString("7f9833fffa3139db133421f7eaae6b7dbc35827162d7c48bbb38d3b05ca288fd4c91cf8a57e07fe51dbcb02c2bfc3df3c2c95328d3428caf0d47040319f28c26061b1e928006d2b6c5eda9889ba6ef8a711b8c0c0d2ab34e1b3ea7ba77582c6b738d48878ffd3900961c772693dce7518c59b7db5b17660928b8583a2a92247c5f56306cd1f948e784741c5ac962f2dbcf411eab33d42bbb6a25dd50d0e75aeb170f7a95b26803132c13da1c11e2a0045987374e8226bf1f9ff53616fd686c29926216b6f6e0a5719cb541a34b3171b354ac9725f9351c2885f613e761119b28733ad627cc22c7e09b4d2455e5b8bdef46f7966c06a6116d87bc162afe6763664a3f91b554494412e4e48afef92e68d68caf4b5e5e229fda4adf9a8812ff4aeebc4eb7aff4b3d3cff9f4384fd98c845497fa6ade3b013691788dd15a2a7fa129aa11542cf6452a03a9fe50ad7af926fd6601552c52f7e2f17dc17eb8bd0aaf03ed30ca651c755a708ca10483ed254e2dc714c91b7d0e9bcfe34918908f69f0b2", 16)
)

func GetParameters() (*big.Int, *big.Int) {
	return p, g
}

// =============================================
// Funções de Criptografia
// =============================================

func Encrypt(pub *PublicKey, msg []byte) (*big.Int, *big.Int, error) {
	m := new(big.Int).SetBytes(msg)
	if m.Cmp(pub.P) >= 0 {
		return nil, nil, errors.New("mensagem muito grande para este valor de p")
	}

	k, err := rand.Int(rand.Reader, new(big.Int).Sub(pub.P, two))
	if err != nil {
		return nil, nil, err
	}
	k.Add(k, one) // garantir 1 ≤ k ≤ p-2

	c1 := new(big.Int).Exp(pub.G, k, pub.P)
	s := new(big.Int).Exp(pub.Y, k, pub.P)
	c2 := new(big.Int).Mod(new(big.Int).Mul(m, s), pub.P)

	return c1, c2, nil
}

func Decrypt(priv *PrivateKey, c1, c2 *big.Int) ([]byte, error) {
	s := new(big.Int).Exp(c1, priv.X, priv.P)
	sInv := new(big.Int).ModInverse(s, priv.P)
	if sInv == nil {
		return nil, errors.New("não foi possível inverter s")
	}
	m := new(big.Int).Mod(new(big.Int).Mul(c2, sInv), priv.P)
	return m.Bytes(), nil
}

// =============================================
// Funções de Assinatura Digital
// =============================================

func generateCoprimeK(p *big.Int) *big.Int {
	pMinus1 := new(big.Int).Sub(p, one)
	for {
		k, err := rand.Int(rand.Reader, pMinus1)
		if err != nil {
			continue
		}
		if k.Cmp(one) <= 0 {
			continue
		}
		if new(big.Int).GCD(nil, nil, k, pMinus1).Cmp(one) == 0 {
			return k
		}
	}
}

func Sign(priv *PrivateKey, hash []byte) (*big.Int, *big.Int, error) {
	k := generateCoprimeK(priv.P)
	pMinus1 := new(big.Int).Sub(priv.P, one)

	m := new(big.Int).SetBytes(hash)
	r := new(big.Int).Exp(priv.G, k, priv.P)
	xr := new(big.Int).Mod(new(big.Int).Mul(priv.X, r), pMinus1)
	hmxr := new(big.Int).Sub(m, xr)

	kInv := new(big.Int).ModInverse(k, pMinus1)
	if kInv == nil {
		return nil, nil, errors.New("não foi possível calcular o inverso de k")
	}

	s := new(big.Int).Mod(new(big.Int).Mul(hmxr, kInv), pMinus1)
	if s.Cmp(zero) < 0 {
		s.Add(s, pMinus1)
	}

	return r, s, nil
}

func Verify(pub *PublicKey, hash []byte, r, s *big.Int) (bool, error) {
	if r.Cmp(one) < 0 || r.Cmp(pub.P) >= 0 {
		return false, errors.New("r fora do intervalo válido")
	}
	if s.Cmp(one) < 0 || s.Cmp(new(big.Int).Sub(pub.P, one)) >= 0 {
		return false, errors.New("s fora do intervalo válido")
	}

	m := new(big.Int).SetBytes(hash)
	ghm := new(big.Int).Exp(pub.G, m, pub.P)
	yrs := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(pub.Y, r, pub.P),
			new(big.Int).Exp(r, s, pub.P),
		),
		pub.P,
	)

	return ghm.Cmp(yrs) == 0, nil
}

// Funções auxiliares para geração de chaves
func GenerateKeys() (*PrivateKey, *PublicKey, error) {
	x, err := rand.Int(rand.Reader, new(big.Int).Sub(p, two))
	if err != nil {
		return nil, nil, err
	}
	x.Add(x, one)
	y := new(big.Int).Exp(g, x, p)
	
	priv := &PrivateKey{P: p, G: g, X: x}
	pub := &PublicKey{P: p, G: g, Y: y}
	
	return priv, pub, nil
}
