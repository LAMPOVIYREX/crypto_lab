package crypto

import (
	"bytes"
)

// Encrypt шифрует данные
func Encrypt(data []byte, key []byte) []byte {
	data = Permute(data, key)
	data = Substitute(data, key)
	data = Permute(data, key)
	data = Substitute(data, key)
	return data
}

// Decrypt расшифровывает данные
func Decrypt(data []byte, key []byte) []byte {
	data = InverseSubstitute(data, key)
	data = InversePermute(data, key)
	data = InverseSubstitute(data, key)
	data = InversePermute(data, key)
	return data
}

// Перестановочный модуль
func Permute(data []byte, key []byte) []byte {
	var result bytes.Buffer
	for i := len(data) - 1; i >= 0; i-- {
		result.WriteByte(data[i])
	}
	return result.Bytes()
}

// Подстановочный модуль
func Substitute(data []byte, key []byte) []byte {
	for i := range data {
		data[i] ^= key[i%len(key)]
	}
	return data
}

// Обратная подстановка
func InverseSubstitute(data []byte, key []byte) []byte {
	for i := range data {
		data[i] ^= key[i%len(key)]
	}
	return data
}

// Обратная перестановка
func InversePermute(data []byte, key []byte) []byte {
	var result bytes.Buffer
	for i := len(data) - 1; i >= 0; i-- {
		result.WriteByte(data[i])
	}
	return result.Bytes()
}
