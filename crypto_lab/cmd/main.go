package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"crypto_lab/crypto"
	"crypto_lab/utils"
)

func processSingleFile(inputPath, outputPath string, key []byte, encrypt bool, logger *log.Logger, verbose bool) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}
	if verbose {
		logger.Printf("Read %d bytes from file: %s\n", len(data), inputPath)
	}

	start := time.Now()
	var result []byte
	if encrypt {
		result = crypto.Encrypt(data, key)
	} else {
		result = crypto.Decrypt(data, key)
	}
	elapsed := time.Since(start)

	// Создаем директорию для выходного файла, если её нет
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	if err := os.WriteFile(outputPath, result, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}

	if verbose {
		action := "Encrypted"
		if !encrypt {
			action = "Decrypted"
		}
		logger.Printf("%s file saved to %s (%v)\n", action, outputPath, elapsed)
	}
	return nil
}

func processDirectory(inputDir, outputDir string, key []byte, encrypt bool, logger *log.Logger, verbose bool) error {
	if verbose {
		logger.Printf("Processing directory: %s -> %s\n", inputDir, outputDir)
	}

	// Создаем корневую выходную директорию
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	return filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing path %q: %v", path, err)
		}

		// Пропускаем директории (их структура будет создана при обработке файлов)
		if info.IsDir() {
			if verbose {
				logger.Printf("Skipping directory: %s\n", path)
			}
			return nil
		}

		// Получаем относительный путь
		relPath, err := filepath.Rel(inputDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path for %q: %v", path, err)
		}

		// Формируем выходной путь
		outputPath := filepath.Join(outputDir, relPath)
		if verbose {
			logger.Printf("Processing file: %s -> %s\n", path, outputPath)
		}

		return processSingleFile(path, outputPath, key, encrypt, logger, verbose)
	})
}

func main() {
	mode := flag.String("mode", "encrypt", "Mode: encrypt or decrypt")
	input := flag.String("dir", "", "Directory or file to process (required)")
	password := flag.String("password", "", "Password phrase (required)")
	output := flag.String("output", "", "Output file or directory name (required)")
	verbose := flag.Bool("verbose", false, "Enable verbose mode")
	flag.Parse()

	// Валидация аргументов
	if *input == "" || *password == "" || *output == "" {
		log.Fatal("Error: All arguments --dir, --password and --output are required")
	}

	// Настройка логгера
	logger := utils.SetupLogger("logs/app.log")
	if *verbose {
		logger.Println("Verbose mode enabled")
		logger.Printf("Starting in %s mode\n", *mode)
		logger.Printf("Input: %s\n", *input)
		logger.Printf("Output: %s\n", *output)
	}

	// Генерация ключа
	key := utils.GenerateKey(*password)
	if *verbose {
		logger.Printf("Generated key: %x\n", key)
	}

	encrypt := *mode == "encrypt"

	// Проверка типа входных данных (файл или директория)
	fileInfo, err := os.Stat(*input)
	if err != nil {
		logger.Fatalf("Error accessing input: %v", err)
	}

	startTotal := time.Now()
	if fileInfo.IsDir() {
		// Обработка директории
		if err := processDirectory(*input, *output, key, encrypt, logger, *verbose); err != nil {
			logger.Fatalf("Directory processing failed: %v", err)
		}
	} else {
		// Обработка одиночного файла
		if err := processSingleFile(*input, *output, key, encrypt, logger, *verbose); err != nil {
			logger.Fatalf("File processing failed: %v", err)
		}
	}

	elapsedTotal := time.Since(startTotal)
	logger.Printf("Operation completed successfully in %v\n", elapsedTotal)
}
