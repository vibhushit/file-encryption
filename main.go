package main

import (
	"encoding/json"
	"file-encryption/decryption"
	"file-encryption/encryption"
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

const hashStoreFile = "hashStore.json"

func saveHashStore(hashStore map[string][]byte) error {
	data, err := json.Marshal(hashStore)
	if err != nil {
		return err
	}
	return os.WriteFile(hashStoreFile, data, 0644)
}

func loadHashStore() (map[string][]byte, error) {
	data, err := os.ReadFile(hashStoreFile)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string][]byte), nil
		}
		return nil, err
	}
	var hashStore map[string][]byte
	err = json.Unmarshal(data, &hashStore)
	if err != nil {
		return nil, err
	}
	return hashStore, nil
}

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Printf("Error loading .env file: %v\n", err)
		return
	}

	hashStore, err := loadHashStore()
	if err != nil {
		fmt.Printf("Error loading hash store: %v\n", err)
		return
	}

	sourceDir := os.Getenv("SOURCE_DIR")
	//cloudDir := os.Getenv("CLOUD_DIR")
	destDir := os.Getenv("DEST_DIR")
	password := os.Getenv("PASSWORD")

	for {
		fmt.Println("\n1. Encryption")
		fmt.Println("2. Decryption")
		fmt.Println("3. Exit")
		fmt.Print("Enter your choice: ")

		var choice int
		fmt.Scan(&choice)

		switch choice {
		case 1:
			err := encryption.EncryptDirectory(sourceDir, password, hashStore)
			if err != nil {
				fmt.Printf("Error during encryption: %v\n", err)
			} else {
				err = saveHashStore(hashStore)
				if err != nil {
					fmt.Printf("Error saving hash store: %v\n", err)
				} else {
					fmt.Println("Files encrypted and hash values stored.")
					//fmt.Printf("HashStore after encryption: %v\n", hashStore)
				}
			}

		case 2:
			//fmt.Printf("HashStore before decryption: %v\n", hashStore)
			err := decryption.DecryptDirectory(destDir, password, hashStore)
			if err != nil {
				fmt.Printf("Error during decryption: %v\n", err)
			}

		case 3:
			fmt.Println("Exiting program...")
			return

		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}
