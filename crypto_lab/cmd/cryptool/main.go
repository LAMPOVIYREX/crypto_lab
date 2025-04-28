package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LAMPOVIYREX/crypto_lab/internal/cipher"
	"github.com/LAMPOVIYREX/crypto_lab/internal/fileutils"
)

func main() {

	encrypt := flag.Bool("encrypt", false, "Режим шифрования")
	decrypt := flag.Bool("decrypt", false, "Режим расшифрования")
	input := flag.String("input", "", "Входной файл или каталог")
	output := flag.String("output", "", "Выходной файл или каталог")
	passphrase := flag.String("passphrase", "", "Парольная фраза")
	verbose := flag.Bool("verbose", false, "Подробный вывод")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags)

	if (*encrypt && *decrypt) || (!*encrypt && !*decrypt) {
		logger.Fatal("Необходимо указать либо -encrypt, либо -decrypt")
	}
	if *input == "" {
		logger.Fatal("Необходимо указать входной файл или каталог (-input)")
	}
	if *passphrase == "" {
		logger.Fatal("Необходимо указать парольную фразу (-passphrase)")
	}

	if _, err := os.Stat(*input); os.IsNotExist(err) {
		logger.Fatalf("Входной путь не существует: %s", *input)
	}

	crypto := cipher.NewCryptoSystem(*verbose, logger)

	salt := []byte("fixed-salt")
	key := cipher.GenerateKeyFromPassphrase(*passphrase, salt)

	if *verbose {
		logger.Println("Ключ шифрования сгенерирован")
		logger.Printf("Длина ключа: %d байт\n", len(key))
	}

	startTime := time.Now()

	var err error
	if *encrypt {
		err = process(*input, *output, fileutils.EncryptFile, crypto, key, *verbose, logger)
	} else {
		err = process(*input, *output, fileutils.DecryptFile, crypto, key, *verbose, logger)

		if err == nil && *output != "" {
			createDecryptedTextFile(*output, logger, *verbose)
		}
	}

	if err != nil {
		logger.Fatalf("Ошибка операции: %v", err)
	}

	if *verbose {
		logger.Printf("Операция завершена за %s\n", time.Since(startTime))
	}
}

func createDecryptedTextFile(outputPath string, logger *log.Logger, verbose bool) {
	content, err := ioutil.ReadFile(outputPath)
	if err != nil {
		logger.Printf("Ошибка чтения расшифрованного файла: %v\n", err)
		return
	}

	decryptedPath := outputPath + ".decrypted.txt"
	if err := ioutil.WriteFile(decryptedPath, content, 0644); err != nil {
		logger.Printf("Ошибка создания файла с текстом: %v\n", err)
	} else if verbose {
		logger.Printf("Создан файл с расшифрованным текстом: %s\n", decryptedPath)
	}
}

func process(input, output string,
	opFunc func(string, string, *cipher.CryptoSystem, []byte, bool, *log.Logger) error,
	crypto *cipher.CryptoSystem, key []byte, verbose bool, logger *log.Logger) error {

	info, err := os.Stat(input)
	if err != nil {
		return err
	}

	if info.IsDir() {

		return filepath.Walk(input, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				relPath, err := filepath.Rel(input, path)
				if err != nil {
					return err
				}

				outPath := filepath.Join(output, relPath)
				if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
					return err
				}

				if verbose {
					logger.Printf("Обработка файла: %s -> %s\n", path, outPath)
				}

				return opFunc(path, outPath, crypto, key, verbose, logger)
			}
			return nil
		})
	}

	if output == "" {
		if strings.HasSuffix(input, ".enc") {
			output = strings.TrimSuffix(input, ".enc")
		} else {
			output = input + ".enc"
		}
	}

	if verbose {
		logger.Printf("Обработка файла: %s -> %s\n", input, output)
	}

	return opFunc(input, output, crypto, key, verbose, logger)
}
