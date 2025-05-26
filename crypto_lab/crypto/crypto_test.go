package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	data := []byte("Hello, world!")

	// Шифрование данных
	encrypted := Encrypt(data, key)

	// Дешифрование данных
	decrypted := Decrypt(encrypted, key)

	// Проверка результата
	if !bytes.Equal(data, decrypted) {
		t.Errorf("Decryption failed. Expected %s, got %s", data, decrypted)
	}
}
