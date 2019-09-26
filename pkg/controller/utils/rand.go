package utils

import (
	"crypto/rand"
)

func RandomPassword(length int) (string, error) {
	byts := make([]byte, length)
	_, err := rand.Read(byts)

	return string(byts), err
}
