package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"file-encryption/utils"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/joho/godotenv"
)

// ScanDirectory scans the given source directory for all its files
func ScanDirectory(srcDir string, tasks chan<- string) error {
	defer close(tasks)
	err := filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			tasks <- path
		}
		return nil
	})
	return err
}

// ComputeAndStoreHashStream computes the hash value for the encrypted file in a streaming manner and stores it in the hashStore map.
func ComputeAndStoreHashStream(filePath string, hashStore map[string][]byte) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}

	hash := hasher.Sum(nil)
	hashStore[filePath] = hash
	return nil
}

// // ComputeAndStoreHash computes the hash value for the encrypted file and stores it in the hashStore map.
// func ComputeAndStoreHash(filePath string, hashStore map[string][]byte) error {
// 	content, err := readFile(filePath)
// 	if err != nil {
// 		return err
// 	}
// 	hash := utils.ComputeHash(content)
// 	hashStore[filePath] = hash
// 	return nil
// }

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
	tasks := make(chan string, 100) // Buffered channel to hold file paths

	// Get the number of logical CPUs
	numWorkers := runtime.NumCPU()

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
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
				err = EncryptFileStream(path, dstPath, []byte(password))
				if err != nil {
					fmt.Printf("Error encrypting file: %v\n", err)
					continue
				}
				err = ComputeAndStoreHashStream(dstPath, hashStore)
				if err != nil {
					fmt.Printf("Error computing hash: %v\n", err)
					continue
				}
				fmt.Printf("Encrypted %s to %s\n", path, dstPath)
			}
		}()
	}

	// Scan the directory and send tasks to the workers
	err = ScanDirectory(srcDir, tasks)
	if err != nil {
		return err
	}

	wg.Wait()
	fmt.Println("Files encrypted and hash values stored.")
	return nil
}

// EncryptFileStream encrypts a large file in a streaming manner.
func EncryptFileStream(srcPath, dstPath string, password []byte) error {
	// Open the source file for reading
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("error opening source file: %v", err)
	}
	defer srcFile.Close()

	// Open the destination file for writing
	dstFile, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("error creating destination file: %v", err)
	}
	defer dstFile.Close()

	// Generate the encryption key and salt
	key, salt, err := utils.GenerateKey(password, nil)
	if err != nil {
		return fmt.Errorf("error generating key: %v", err)
	}

	// Write the salt to the destination file
	_, err = dstFile.Write(salt)
	if err != nil {
		return fmt.Errorf("error writing salt: %v", err)
	}

	// Create the AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating AES cipher block: %v", err)
	}

	// Create the GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creating GCM mode: %v", err)
	}

	// Generate a nonce
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return fmt.Errorf("error generating nonce: %v", err)
	}

	// Write the nonce to the destination file
	_, err = dstFile.Write(nonce)
	if err != nil {
		return fmt.Errorf("error writing nonce: %v", err)
	}

	// Create a buffer to hold chunks of the file
	buffer := make([]byte, 1024*1024*100) // 1 MB buffer

	for {
		// Read a chunk from the source file
		n, err := srcFile.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading from source file: %v", err)
		}
		if n == 0 {
			break
		}

		// Encrypt the chunk
		ciphertext := gcm.Seal(nil, nonce, buffer[:n], nil)

		// Write the encrypted chunk to the destination file
		_, err = dstFile.Write(ciphertext)
		if err != nil {
			return fmt.Errorf("error writing to destination file: %v", err)
		}
	}

	return nil
}
