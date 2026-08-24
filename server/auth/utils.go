package auth

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// hashes a password with bcrypt at cost factor 10 (2^10 rounds)
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// containsSpace reports whether s has any whitespace character anywhere in
// it (not just leading/trailing) -- unicode.IsSpace so tabs/newlines/unicode
// spaces are caught too, not just the literal " " character.
func containsSpace(s string) bool {
	return strings.IndexFunc(s, unicode.IsSpace) != -1
}

//generate a cryptographically pseudorandom bitstream to use as a session token
func generateToken(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("failed to generate token: %v", err)
	}

	return base64.URLEncoding.EncodeToString(bytes)
}
