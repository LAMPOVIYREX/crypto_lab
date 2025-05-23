package fileutils

import (
	"fmt"
	"io/ioutil"
	"log"

	"crypto_lab/internal/cipher"
)

// EncryptFile шифрует файл с использованием режима CBC.
func EncryptFile(inputPath, outputPath string, cs *cipher.CryptoSystem, key []byte, verbose bool, logger *log.Logger) error {
	// Чтение входного файла
	data, err := ioutil.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	// Генерация случайного IV
	iv, err := cipher.GenerateIV(cipher.BlockSize)
	if err != nil {
		return fmt.Errorf("failed to generate IV: %v", err)
	}

	// Шифрование данных
	encrypted, err := cs.Encrypt(data, key, iv)
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	// Добавление IV в начало зашифрованных данных
	encrypted = append(iv, encrypted...)

	// Запись зашифрованных данных в выходной файл
	err = ioutil.WriteFile(outputPath, encrypted, 0644)
	if err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}

	if verbose {
		logger.Printf("Файл успешно зашифрован: %s -> %s\n", inputPath, outputPath)
	}

	return nil
}

// DecryptFile расшифровывает файл с использованием режима CBC.
func DecryptFile(inputPath, outputPath string, cs *cipher.CryptoSystem, key []byte, verbose bool, logger *log.Logger) error {
	// Чтение зашифрованного файла
	data, err := ioutil.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	// Проверка длины данных (должен быть как минимум IV)
	if len(data) < cipher.BlockSize {
		return fmt.Errorf("invalid ciphertext: too short")
	}

	// Извлечение IV из начала данных
	iv := data[:cipher.BlockSize]
	ciphertext := data[cipher.BlockSize:]

	// Расшифровка данных
	decrypted, err := cs.Decrypt(ciphertext, key, iv)
	if err != nil {
		return fmt.Errorf("decryption failed: %v", err)
	}

	// Запись расшифрованных данных в выходной файл
	err = ioutil.WriteFile(outputPath, decrypted, 0644)
	if err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}

	if verbose {
		logger.Printf("Файл успешно расшифрован: %s -> %s\n", inputPath, outputPath)
	}

	return nil
}
