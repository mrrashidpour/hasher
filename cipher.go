package hasher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

// Cipher برای رمزنگاری دوطرفه با AES-256-CBC
type Cipher struct {
	key []byte
}

// NewCipher ایجاد رمزنگار با کلید (هر رشته‌ای می‌تواند باشد)
func NewCipher(key string) *Cipher {
	hash := sha256.Sum256([]byte(key))
	return &Cipher{key: hash[:]}
}

func (c *Cipher) base64Encode(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")
	return strings.TrimRight(encoded, "=")
}

func (c *Cipher) base64Decode(data string) ([]byte, error) {
	decoded := strings.ReplaceAll(data, "-", "+")
	decoded = strings.ReplaceAll(decoded, "_", "/")

	switch len(decoded) % 4 {
	case 2:
		decoded += "=="
	case 3:
		decoded += "="
	}

	return base64.StdEncoding.DecodeString(decoded)
}

// Encrypt رمزنگاری هر نوع داده با انقضا بر حسب دقیقه (0 = بدون انقضا)
func (c *Cipher) Encrypt(data interface{}, expireMinutes int) (string, error) {
	payload := struct {
		Data   interface{} `json:"data"`
		Expire int64       `json:"expire"`
	}{
		Data:   data,
		Expire: 0,
	}

	if expireMinutes > 0 {
		payload.Expire = time.Now().Unix() + int64(expireMinutes*60)
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}

	paddedData := pkcs7Pad(jsonData, aes.BlockSize)
	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	result := append(iv, ciphertext...)
	return c.base64Encode(result), nil
}

// Decrypt رمزگشایی و برگرداندن داده اصلی
func (c *Cipher) Decrypt(encrypted string) (interface{}, error) {
	data, err := c.base64Decode(encrypted)
	if err != nil || len(data) < 16 {
		return nil, errors.New("invalid data")
	}

	iv := data[:16]
	ciphertext := data[16:]

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("invalid ciphertext")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	plaintext, err = pkcs7Unpad(plaintext)
	if err != nil {
		return nil, errors.New("decryption failed")
	}

	var payload struct {
		Data   interface{} `json:"data"`
		Expire int64       `json:"expire"`
	}

	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, errors.New("invalid data format")
	}

	if payload.Expire > 0 && payload.Expire < time.Now().Unix() {
		return nil, errors.New("data expired")
	}

	return payload.Data, nil
}

// pkcs7Pad padding برای AES
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

// pkcs7Unpad حذف padding
func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid padding")
	}

	padding := int(data[length-1])
	if padding > length || padding > aes.BlockSize {
		return nil, errors.New("invalid padding")
	}

	return data[:length-padding], nil
}
