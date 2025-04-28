package cipher

import (
	"bytes"
	"errors"
)

// padData добавляет padding к данным по PKCS#7
func padData(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// unpadData удаляет padding по PKCS#7
func unpadData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	padding := int(data[len(data)-1])
	if padding > len(data) {
		return nil, errors.New("invalid padding")
	}
	return data[:len(data)-padding], nil
}

// xorBytes выполняет операцию XOR между двумя байтовыми массивами
func xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i%len(b)]
	}
	return result
}
