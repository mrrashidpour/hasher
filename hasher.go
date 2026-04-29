package hasher

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// KeyedHasher هش‌کننده یکطرفه با کلید مخفی
type KeyedHasher struct {
	secret []byte
}

// NewKeyedHasher ایجاد هش‌کننده با کلید مخفی
func NewKeyedHasher(secretKey string) *KeyedHasher {
	return &KeyedHasher{
		secret: []byte(secretKey),
	}
}

// Hash هش کردن متن با کلید مخفی (نتیجه همیشه ثابت برای ورودی یکسان)
func (k *KeyedHasher) Hash(text string) string {
	h := hmac.New(sha256.New, k.secret)
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}

// HashBytes هش کردن داده باینری با کلید مخفی
func (k *KeyedHasher) HashBytes(data []byte) string {
	h := hmac.New(sha256.New, k.secret)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// Verify بررسی صحت متن با هش ذخیره شده
func (k *KeyedHasher) Verify(text, hashedText string) bool {
	return k.Hash(text) == hashedText
}
