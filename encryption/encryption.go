package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"file-encryption/utils"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/joho/godotenv"
)

func EncryptDirectory(srcDir, password string, hashStore map[string][]byte) error {
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

	var wg sync.WaitGroup
	tasks := make(chan string)

	// Start worker goroutines
	for i := 0; i < 4; i++ { // Adjust the number of workers as needed
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range tasks {
				relPath, err := filepath.Rel(srcDir, path)
				if err != nil {
					fmt.Printf("Error getting relative path: %v\n", err)
					continue
				}
				dstPath := filepath.Join(cloudDir, relPath+".gpg")
				err = os.MkdirAll(filepath.Dir(dstPath), os.ModePerm)
				if err != nil {
					fmt.Printf("Error creating directory: %v\n", err)
					continue
				}
				hash, err := encryptFile(path, dstPath, []byte(password))
				if err != nil {
					fmt.Printf("Error encrypting file: %v\n", err)
					continue
				}
				hashStore[dstPath] = hash
				fmt.Printf("Encrypted %s to %s\n", path, dstPath)
				//fmt.Printf("Path: %s, Hash: %x\n", dstPath, hash)
			}
		}()
	}

	// Traverse the directory and send tasks to the workers
	err = filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
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
	fmt.Println("Files encrypted and hash values stored.")
	// for path, hash := range hashStore {
	// 	fmt.Printf("Path: %s, Hash: %x\n", path, hash)
	// }
	return nil
}

func encryptFile(srcPath, dstPath string, password []byte) ([]byte, error) {
	srcBytes, err := readFile(srcPath)
	if err != nil {
		return nil, err
	}

	key, salt, err := utils.GenerateKey(password, nil)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("Encryption Key: %s\n", hex.EncodeToString(key))
	// fmt.Printf("Salt: %s\n", hex.EncodeToString(salt))

	//nonce, ciphertext, err := encryptContent(srcBytes, key)
	_, ciphertext, err := encryptContent(srcBytes, key)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("Nonce: %s\n", hex.EncodeToString(nonce))
	// fmt.Printf("Ciphertext during encryption: %s\n", hex.EncodeToString(ciphertext))

	err = writeFile(dstPath, salt, ciphertext)
	if err != nil {
		return nil, err
	}

	hash := utils.ComputeHash(ciphertext)
	return hash, nil
}

func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return nil, err
	}
	defer file.Close()

	return io.ReadAll(file)
}

func writeFile(path string, salt, content []byte) error {
	file, err := os.Create(path)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return err
	}
	defer file.Close()

	_, err = file.Write(salt)
	if err != nil {
		fmt.Printf("Error writing salt: %v\n", err)
		return err
	}
	_, err = file.Write(content)
	if err != nil {
		fmt.Printf("Error writing content: %v\n", err)
		return err
	}
	return nil
}

func encryptContent(content, key []byte) ([]byte, []byte, error) {
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

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		fmt.Printf("Error generating nonce: %v\n", err)
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, content, nil)
	return nonce, ciphertext, nil
}
