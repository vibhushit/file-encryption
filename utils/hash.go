package utils

import (
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/argon2"
)

// ComputeHash computes the SHA-256 hash of the given data
func ComputeHash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// GenerateKey derives a key from the provided password using the Argon2id algorithm
func GenerateKey(password []byte, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 16) // 16 bytes for the salt
		_, err := rand.Read(salt)
		if err != nil {
			return nil, nil, err
		}
	}

	// Use the recommended parameters for non-interactive operations
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	return key, salt, nil
}
