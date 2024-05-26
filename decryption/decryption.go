package decryption

import (
	"crypto/aes"
	"crypto/cipher"
	"file-encryption/utils"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/joho/godotenv"
)

func DecryptDirectory(dstDir, password string, hashStore map[string][]byte) error {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		fmt.Printf("Error loading .env file: %v\n", err)
		return err
	}

	cloudDir := os.Getenv("CLOUD_DIR")
	if cloudDir == "" {
		return fmt.Errorf("CLOUD_DIR environment variable not set")
	}

	//fmt.Printf("hash store is %v\n", hashStore)
	var wg sync.WaitGroup
	tasks := make(chan string)

	// Start worker goroutines
	for i := 0; i < 4; i++ { // Adjust the number of workers as needed
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range tasks {
				relPath, err := filepath.Rel(cloudDir, path)
				if err != nil {
					fmt.Printf("Error getting relative path: %v\n", err)
					continue
				}
				dstPath := filepath.Join(dstDir, relPath[:len(relPath)-4]) // Remove ".gpg" extension
				err = os.MkdirAll(filepath.Dir(dstPath), os.ModePerm)
				if err != nil {
					fmt.Printf("Error creating directory: %v\n", err)
					continue
				}
				hash, err := decryptFile(path, dstPath, []byte(password))
				if err != nil {
					fmt.Printf("Error decrypting file: %v\n", err)
					continue
				}

				// Verify the hash value
				// storedHash, ok := hashStore[path]
				// if !ok {
				// 	fmt.Printf("Hash value not found for %s\n", path)
				// 	continue
				// }
				// if !bytes.Equal(hash, storedHash) {
				// 	fmt.Printf("Integrity check for %s\n", path)
				// 	//continue
				// }

				fmt.Printf("Decrypted %s to %s\n", path, dstPath)
				fmt.Printf("Path: %s, Hash: %x\n", path, hash)
			}
		}()
	}

	// Traverse the directory and send tasks to the workers
	err = filepath.WalkDir(cloudDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			tasks <- path
		}
		return nil
	})
	close(tasks)
	wg.Wait()

	if err != nil {
		return err
	}
	return nil
}

func decryptFile(srcPath, dstPath string, password []byte) ([]byte, error) {
	salt, ciphertext, err := readFile(srcPath)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("Salt: %s\n", hex.EncodeToString(salt))

	key, _, err := utils.GenerateKey(password, salt)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("Decryption Key: %s\n", hex.EncodeToString(key))

	//nonce, plaintext, err := decryptContent(ciphertext, key)
	_, plaintext, err := decryptContent(ciphertext, key)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("Nonce: %s\n", hex.EncodeToString(nonce))
	//fmt.Printf("Ciphertext during decryption: %s\n", hex.EncodeToString(ciphertext))

	err = writeFile(dstPath, plaintext)
	if err != nil {
		return nil, err
	}

	hash := utils.ComputeHash(plaintext)
	return hash, nil
}

func readFile(path string) ([]byte, []byte, error) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return nil, nil, err
	}
	defer file.Close()

	salt := make([]byte, 16)
	_, err = io.ReadFull(file, salt)
	if err != nil {
		fmt.Printf("Error reading salt: %v\n", err)
		return nil, nil, err
	}

	content, err := io.ReadAll(file)
	if err != nil {
		fmt.Printf("Error reading content: %v\n", err)
		return nil, nil, err
	}

	return salt, content, nil
}

func writeFile(path string, content []byte) error {
	file, err := os.Create(path)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return err
	}
	defer file.Close()

	_, err = file.Write(content)
	if err != nil {
		fmt.Printf("Error writing content: %v\n", err)
		return err
	}
	return nil
}

func decryptContent(content, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("Error creating AES cipher block: %v\n", err)
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Error creating GCM mode: %v\n", err)
		return nil, nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(content) < nonceSize {
		fmt.Printf("Ciphertext is too short\n")
		return nil, nil, fmt.Errorf("ciphertext is too short")
	}
	nonce, ciphertext := content[:nonceSize], content[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Printf("Error decrypting ciphertext: %v\n", err)
		return nil, nil, err
	}

	return nonce, plaintext, nil
}
