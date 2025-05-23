package cipher

import (
	cryptorand "crypto/rand"
	"crypto/sha512"
	"errors"
	"log"
)

const (
	KeySize   = 32
	SaltSize  = 16
	BlockSize = 16
)

type CryptoSystem struct {
	verbose bool
	logger  *log.Logger
}

// генерирует случайный вектор инициализации (IV).
func GenerateIV(blockSize int) ([]byte, error) {
	iv := make([]byte, blockSize)
	_, err := cryptorand.Read(iv)
	return iv, err
}

func Transpose(data []byte) []byte {
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[len(data)-1-i] // Обратный порядок
	}
	return result
}

func NewCryptoSystem(verbose bool, logger *log.Logger) *CryptoSystem {
	return &CryptoSystem{verbose, logger}
}

// генерирует ключ из парольной фразы и соли.
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

// Encrypt шифрует данные с использованием режима CBC.
func (cs *CryptoSystem) Encrypt(plaintext, key, iv []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("invalid key size")
	}

	// Добавляем padding
	plaintext = padData(plaintext, BlockSize)

	// Разделяем на блоки
	blocks := splitIntoBlocks(plaintext, BlockSize)

	ciphertext := []byte{}
	prevBlock := iv

	for _, block := range blocks {
		// Первый перестановочный шаг: изменение порядка байтов
		transposedBlock := Transpose(block)

		// XOR текущего блока с предыдущим зашифрованным блоком
		xoredBlock := xorBytes(transposedBlock, prevBlock)

		// Первый подстановочный шаг: замена байтов на основе ключа
		encryptedBlock := substitute(xoredBlock, key)

		// Добавляем зашифрованный блок к результату
		ciphertext = append(ciphertext, encryptedBlock...)

		// Обновляем предыдущий блок
		prevBlock = encryptedBlock
	}

	return ciphertext, nil
}

// Decrypt расшифровывает данные с использованием режима CBC.
func (cs *CryptoSystem) Decrypt(ciphertext, key, iv []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("invalid key size")
	}

	// Разделяем на блоки
	blocks := splitIntoBlocks(ciphertext, BlockSize)

	plaintext := []byte{}
	prevBlock := iv

	for _, block := range blocks {
		// Подстановочный шаг: замена байтов на основе ключа
		decryptedBlock := substitute(block, key)

		// Перестановочный шаг: изменение порядка байтов
		transposedBlock := Transpose(decryptedBlock)

		// XOR с предыдущим зашифрованным блоком
		plainBlock := xorBytes(transposedBlock, prevBlock)

		// Добавляем расшифрованный блок к результату
		plaintext = append(plaintext, plainBlock...)

		// Обновляем предыдущий блок
		prevBlock = block
	}

	// Удаляем padding
	return unpadData(plaintext)
}
