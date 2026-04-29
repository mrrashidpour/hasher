package hasher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/mrrashidpour/iransanitize"
)

// Hasher ساختار برای هش یک‌طرفه
type Hasher struct{}

// NewHasher ایجاد نمونه جدید
func NewHasher() *Hasher {
	return &Hasher{}
}

// Hash هش کردن یک رشته با SHA256
func (h *Hasher) Hash(text string) string {
	hash := sha256.Sum256([]byte(text))
	return hex.EncodeToString(hash[:])
}

// HashBytes هش کردن داده باینری
func (h *Hasher) HashBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// HashWithSalt هش کردن با نمک
func (h *Hasher) HashWithSalt(text, salt string) string {
	data := text + salt
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Compare مقایسه متن ساده با هش ذخیره شده
func (h *Hasher) Compare(plainText, hashedText string) bool {
	return h.Hash(plainText) == hashedText
}

// CompareWithSalt مقایسه با نمک
func (h *Hasher) CompareWithSalt(plainText, salt, hashedText string) bool {
	return h.HashWithSalt(plainText, salt) == hashedText
}

// HashPhone هش شماره تلفن (نرمالایز شده)
func (h *Hasher) HashPhone(phone string) string {
	phone = iransanitize.SanitizeMobile(phone)

	if strings.HasPrefix(phone, "0") {
		phone = phone[1:]
	}

	return h.Hash(phone)
}

// HashJSON هش کردن محتوای JSON
func (h *Hasher) HashJSON(data interface{}) (string, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return h.HashBytes(bytes), nil
}

// DoubleHash هش دو مرحله‌ای برای امنیت بیشتر
func (h *Hasher) DoubleHash(text string) string {
	firstHash := sha256.Sum256([]byte(text))
	secondHash := sha256.Sum256(firstHash[:])
	return hex.EncodeToString(secondHash[:])
}
