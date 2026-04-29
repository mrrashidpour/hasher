// Package hasher provides cryptographic utilities for hashing and encryption.
//
// # Features
//   - One-way hashing (SHA256) with salt support
//   - Phone number normalization and hashing (Iranian format)
//   - Two-way AES-256-CBC encryption with expiration support
//   - JSON hashing and double-hashing
//
// # Examples
//
//	// One-way hashing
//	h := hasher.NewHasher()
//	hash := h.Hash("mypassword")
//
//	// Encryption
//	c := hasher.NewCipher("mykey")
//	enc, _ := c.Encrypt("secret data", 60) // expires in 60 minutes
//
//	// Decryption
//	dec, _ := c.Decrypt(enc)
package hasher
