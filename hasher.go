package hasher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/mrrashidpour/iransanitize"
)

// Hash هش کردن یک رشته با SHA256
func Hash(text string) string {
	hash := sha256.Sum256([]byte(text))
	return hex.EncodeToString(hash[:])
}

// HashBytes هش کردن داده باینری
func HashBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// HashWithSalt هش کردن با نمک
func HashWithSalt(text, salt string) string {
	data := text + salt
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Compare مقایسه متن ساده با هش ذخیره شده
func Compare(plainText, hashedText string) bool {
	return Hash(plainText) == hashedText
}

// CompareWithSalt مقایسه با نمک
func CompareWithSalt(plainText, salt, hashedText string) bool {
	return HashWithSalt(plainText, salt) == hashedText
}

// HashPhone هش شماره تلفن (نرمالایز شده)
func HashPhone(phone string) string {
	phone = iransanitize.SanitizeMobile(phone)
	return Hash(phone)
}

// HashJSON هش کردن محتوای JSON
func HashJSON(data interface{}) (string, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return HashBytes(bytes), nil
}

// DoubleHash هش دو مرحله‌ای برای امنیت بیشتر
func DoubleHash(text string) string {
	firstHash := sha256.Sum256([]byte(text))
	secondHash := sha256.Sum256(firstHash[:])
	return hex.EncodeToString(secondHash[:])
}
