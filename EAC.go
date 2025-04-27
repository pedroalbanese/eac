package eac

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/pedroalbanese/anubis"
	"github.com/pedroalbanese/cmac"
)

type eacAnubis struct {
	key []byte
}

// NewEAC returns a new AEAD implementation using Anubis in EAC mode.
func NewEAC(key []byte) (cipher.AEAD, error) {
	if len(key) < 16 || len(key) > 40 {
		return nil, errors.New("eac: invalid key size")
	}
	return &eacAnubis{key: key}, nil
}

func (a *eacAnubis) NonceSize() int {
	return 12 // EAC normalmente usa 96 bits (12 bytes) como nonce
}

func (a *eacAnubis) Overhead() int {
	return 16 // Tamanho da tag de autenticação
}

func (a *eacAnubis) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	tagHeader := generate(0x00, additionalData, a.key)
	tagNonce := generate(0x01, nonce, a.key)
	ciphertext := ctrMode(plaintext, a.key, tagNonce)
	tagMessage := generate(0x02, ciphertext, a.key)
	finalTag := xorBytes(xorBytes(tagHeader, tagNonce), tagMessage)

	// ciphertext || tag
	result := make([]byte, len(dst)+len(ciphertext)+len(finalTag))
	copy(result, dst)
	copy(result[len(dst):], ciphertext)
	copy(result[len(dst)+len(ciphertext):], finalTag)

	return result
}

func (a *eacAnubis) Open(dst, nonce, ciphertextAndTag, additionalData []byte) ([]byte, error) {
	if len(ciphertextAndTag) < 16 {
		return nil, errors.New("eac: ciphertext too short")
	}

	ciphertext := ciphertextAndTag[:len(ciphertextAndTag)-16]
	tag := ciphertextAndTag[len(ciphertextAndTag)-16:]

	tagHeader := generate(0x00, additionalData, a.key)
	tagNonce := generate(0x01, nonce, a.key)
	tagMessage := generate(0x02, ciphertext, a.key)
	expectedTag := xorBytes(xorBytes(tagHeader, tagNonce), tagMessage)

	if subtle.ConstantTimeCompare(expectedTag, tag) != 1 {
		return nil, errors.New("eac: authentication failed")
	}

	plaintext := ctrMode(ciphertext, a.key, tagNonce)
	result := make([]byte, len(dst)+len(plaintext))
	copy(result, dst)
	copy(result[len(dst):], plaintext)
	return result, nil
}

// Internal helpers
func generate(tagByte byte, data []byte, key []byte) []byte {
	c, err := anubis.NewWithKeySize(key, len(key))
	if err != nil {
		panic(err)
	}
	mac, err := cmac.New(c)
	if err != nil {
		panic(err)
	}
	mac.Write(append([]byte{tagByte}, data...))
	return mac.Sum(nil)
}

func ctrMode(input, key, iv []byte) []byte {
	block, err := anubis.NewWithKeySize(key, len(key))
	if err != nil {
		panic(err)
	}
	stream := cipher.NewCTR(block, iv)
	output := make([]byte, len(input))
	stream.XORKeyStream(output, input)
	return output
}

func xorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}
