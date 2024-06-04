package decryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

// CheckAndDecryptFile checks the integrity of the encrypted file using the hash value stored earlier and then decrypts the file content to a given location
func CheckAndDecryptFile(srcPath, dstPath string, password []byte, hashStore map[string][]byte) error {
	// Verify the hash value in a streaming manner
	file, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}

	hash := hasher.Sum(nil)
	storedHash, ok := hashStore[srcPath]
	if !ok {
		return fmt.Errorf("hash value not found for %s", srcPath)
	}
	if !bytes.Equal(hash, storedHash) {
		return fmt.Errorf("integrity check failed for %s", srcPath)
	}

	// Decrypt the file
	err = DecryptFileStream(srcPath, dstPath, password)
	if err != nil {
		return err
	}

	fmt.Printf("Decrypted %s to %s\n", srcPath, dstPath)
	return nil
}

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
				err = CheckAndDecryptFile(path, dstPath, []byte(password), hashStore)
				if err != nil {
					fmt.Printf("Error checking and decrypting file: %v\n", err)
					continue
				}
			}
		}()
	}

	// Scan the directory and send tasks to the workers
	err = ScanDirectory(cloudDir, tasks)
	if err != nil {
		return err
	}

	wg.Wait()
	return nil
}

// DecryptFileStream decrypts a large file in a streaming manner.
func DecryptFileStream(srcPath, dstPath string, password []byte) error {
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

	// Read the salt from the source file
	salt := make([]byte, 16)
	_, err = io.ReadFull(srcFile, salt)
	if err != nil {
		return fmt.Errorf("error reading salt: %v", err)
	}

	// Generate the decryption key
	key, _, err := utils.GenerateKey(password, salt)
	if err != nil {
		return fmt.Errorf("error generating key: %v", err)
	}

	// Read the nonce from the source file
	nonce := make([]byte, 12)
	_, err = io.ReadFull(srcFile, nonce)
	if err != nil {
		return fmt.Errorf("error reading nonce: %v", err)
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

	// Create a buffer to hold chunks of the file
	buffer := make([]byte, 1024*1024*100) // 100 MB buffer

	for {
		// Read a chunk from the source file
		n, err := srcFile.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading from source file: %v", err)
		}
		if n == 0 {
			break
		}

		// Decrypt the chunk
		plaintext, err := gcm.Open(nil, nonce, buffer[:n], nil)
		if err != nil {
			return fmt.Errorf("error decrypting chunk: %v", err)
		}

		// Write the decrypted chunk to the destination file
		_, err = dstFile.Write(plaintext)
		if err != nil {
			return fmt.Errorf("error writing to destination file: %v", err)
		}
	}

	return nil
}
