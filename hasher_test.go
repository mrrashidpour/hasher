package hasher

import (
	"testing"
)

func TestHashPhone(t *testing.T) {
	expectedHash := HashPhone("09121234567")

	tests := []struct {
		input    string
		expected string
	}{
		{"09121234567", expectedHash},
		{"0989121234567", expectedHash},
		{"+989121234567", expectedHash},
		{"++989121234567", expectedHash},
		{"00989121234567", expectedHash},
		{"98 912 123 4567", expectedHash},
		{"0989121----234567", expectedHash},
		{"--+98912123-4567", expectedHash},
		{"++9891-2123-4567", expectedHash},
		{"009-8912-123-4567", expectedHash},
		{"9-8 912 12-3 4567", expectedHash},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := HashPhone(tt.input)
			if result != tt.expected {
				t.Errorf("input: %q, expected: %q, got: %q", tt.input, tt.expected, result)
			}
		})
	}
}

func TestCipherEncryptDecrypt(t *testing.T) {
	cipher := NewCipher("my-secret-key")

	original := map[string]string{"name": "test"}
	encrypted, err := cipher.Encrypt(original, 0)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	result, ok := decrypted.(map[string]interface{})
	if !ok {
		t.Fatal("invalid type")
	}

	if result["name"] != "test" {
		t.Errorf("expected test, got %v", result["name"])
	}
}
