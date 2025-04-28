package cipher

import (
	cryptorand "crypto/rand"
	"crypto/sha512"
	"errors"
	"log"
)

const (
	KeySize  = 32
	SaltSize = 16
)

type CryptoSystem struct {
	verbose bool
	logger  *log.Logger
}

func NewCryptoSystem(verbose bool, logger *log.Logger) *CryptoSystem {
	return &CryptoSystem{verbose, logger}
}

// Изменено с GenerateKey на GenerateKeyFromPassphrase
func GenerateKeyFromPassphrase(passphrase string, salt []byte) []byte {
	hash := sha512.New()
	hash.Write([]byte(passphrase))
	hash.Write(salt)
	return hash.Sum(nil)[:KeySize]
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	_, err := cryptorand.Read(salt)
	return salt, err
}

func (cs *CryptoSystem) Encrypt(plaintext, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("invalid key size")
	}

	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	for i := range plaintext {
		ciphertext[i] = plaintext[i] ^ key[i%len(key)]
	}

	return append(salt, ciphertext...), nil
}

func (cs *CryptoSystem) Decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("invalid key size")
	}

	if len(ciphertext) <= SaltSize {
		return nil, errors.New("ciphertext too short")
	}

	data := ciphertext[SaltSize:]
	plaintext := make([]byte, len(data))

	for i := range data {
		plaintext[i] = data[i] ^ key[i%len(key)]
	}

	return plaintext, nil
}
