package utils

import (
	"crypto/rand"
	"encoding/base64"
)

func RandomPassword(length int) (string, error) {
	byts := make([]byte, length)
	_, err := rand.Read(byts)

	return base64.URLEncoding.EncodeToString(byts), err
}
