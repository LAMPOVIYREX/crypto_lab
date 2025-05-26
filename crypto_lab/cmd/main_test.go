package main

import (
	"bytes"
	"crypto_lab/utils"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func TestProcessDirectory(t *testing.T) {
	// Создание временной директории
	tempDir, err := ioutil.TempDir("", "testdir")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Создание подкаталога и тестовых файлов
	subDir := filepath.Join(tempDir, "subdir")
	err = os.Mkdir(subDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	file1 := filepath.Join(tempDir, "file1.txt")
	file2 := filepath.Join(subDir, "file2.txt")
	err = ioutil.WriteFile(file1, []byte("Hello, file1!"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	err = ioutil.WriteFile(file2, []byte("Hello, file2!"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Генерация ключа
	password := "mypassword"
	key := utils.GenerateKey(password)

	// Создание выходной директории
	outputDir, err := ioutil.TempDir("", "outputdir")
	if err != nil {
		t.Fatalf("Failed to create output directory: %v", err)
	}
	defer os.RemoveAll(outputDir)

	// Настройка логгера
	logger := log.New(os.Stdout, "", log.LstdFlags)

	// Шифрование каталога
	err = processDirectory(tempDir, outputDir, key, true, logger, false)
	if err != nil {
		t.Fatalf("processDirectory (encrypt) failed: %v", err)
	}

	// Проверка, что файлы зашифрованы
	encryptedFile1 := filepath.Join(outputDir, "file1.txt")
	encryptedFile2 := filepath.Join(outputDir, "subdir", "file2.txt")

	encryptedData1, err := ioutil.ReadFile(encryptedFile1)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}
	if bytes.Equal(encryptedData1, []byte("Hello, file1!")) {
		t.Errorf("File was not encrypted")
	}

	encryptedData2, err := ioutil.ReadFile(encryptedFile2)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}
	if bytes.Equal(encryptedData2, []byte("Hello, file2!")) {
		t.Errorf("File was not encrypted")
	}

	// Дешифрование каталога
	decryptedDir, err := ioutil.TempDir("", "decrypteddir")
	if err != nil {
		t.Fatalf("Failed to create decrypted directory: %v", err)
	}
	defer os.RemoveAll(decryptedDir)

	err = processDirectory(outputDir, decryptedDir, key, false, logger, false)
	if err != nil {
		t.Fatalf("processDirectory (decrypt) failed: %v", err)
	}

	// Проверка, что файлы дешифрованы
	decryptedFile1 := filepath.Join(decryptedDir, "file1.txt")
	decryptedFile2 := filepath.Join(decryptedDir, "subdir", "file2.txt")

	decryptedData1, err := ioutil.ReadFile(decryptedFile1)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}
	if !bytes.Equal(decryptedData1, []byte("Hello, file1!")) {
		t.Errorf("Decryption failed. Expected 'Hello, file1!', got '%s'", decryptedData1)
	}

	decryptedData2, err := ioutil.ReadFile(decryptedFile2)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}
	if !bytes.Equal(decryptedData2, []byte("Hello, file2!")) {
		t.Errorf("Decryption failed. Expected 'Hello, file2!', got '%s'", decryptedData2)
	}
}
