package fileutils

import (
	"io/ioutil"
	"log"

	"github.com/LAMPOVIYREX/crypto_lab/internal/cipher"
)

func EncryptFile(inputPath, outputPath string, cs *cipher.CryptoSystem, key []byte, verbose bool, logger *log.Logger) error {
	data, err := ioutil.ReadFile(inputPath)
	if err != nil {
		return err
	}

	encrypted, err := cs.Encrypt(data, key)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(outputPath, encrypted, 0644)
}

func DecryptFile(inputPath, outputPath string, cs *cipher.CryptoSystem, key []byte, verbose bool, logger *log.Logger) error {
	data, err := ioutil.ReadFile(inputPath)
	if err != nil {
		return err
	}

	decrypted, err := cs.Decrypt(data, key)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(outputPath, decrypted, 0644)
}
