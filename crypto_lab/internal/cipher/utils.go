package cipher

import (
	"bytes"
	"errors"
)

// padData добавляет padding к данным для выравнивания по размеру блока.
func padData(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// unpadData удаляет padding из данных.
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

// splitIntoBlocks разделяет данные на блоки фиксированного размера.
func splitIntoBlocks(data []byte, blockSize int) [][]byte {
	var blocks [][]byte
	for i := 0; i < len(data); i += blockSize {
		end := i + blockSize
		if end > len(data) {
			end = len(data)
		}
		blocks = append(blocks, data[i:end])
	}
	return blocks
}

// xorBytes выполняет побитовую операцию XOR между двумя массивами байтов.
func xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i%len(b)]
	}
	return result
}

// substitute выполняет подстановку данных с использованием ключа.
func substitute(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}
