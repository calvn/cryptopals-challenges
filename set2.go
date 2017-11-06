package cryptopals

import (
	"crypto/aes"
	"fmt"
)

func pad(block []byte, length int) []byte {
	result := make([]byte, length)
	copy(result, block)

	// remainder = k - (l mod k)
	remainder := length - (len(block) % length)
	if remainder != length {
		for i := len(block); i < length; i++ {
			result[i] = byte(4)
		}
	}

	return result
}

// Challenge9 - Implement PKCS#7 padding
func Challenge9(in []byte) ([]byte, error) {
	return pad(in, 20), nil
}

// cbcEncrypt performs CBC encryption. plaintext has to be padded.
// More info on CBC: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29
func cbcEncrypt(plaintext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(plaintext)%blockSize != 0 {
		return nil, fmt.Errorf("plaintext not a multiple of blocksize")
	}

	if len(iv) != blockSize {
		return nil, fmt.Errorf("iv and blocksize does not match")
	}

	ciphertext := make([]byte, len(plaintext))
	xorVal := iv
	for i := 0; i < len(ciphertext); i += blockSize {
		xored, err := xor(plaintext[i:i+blockSize], xorVal)
		if err != nil {
			return nil, err
		}
		block.Encrypt(ciphertext[i:i+blockSize], xored)
		xorVal = ciphertext[i : i+blockSize]
	}

	return ciphertext, nil
}

func cbcDecrypt(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("plaintext not a multiple of blocksize")
	}

	if len(iv) != blockSize {
		return nil, fmt.Errorf("iv and blocksize does not match")
	}

	plaintext := make([]byte, len(ciphertext))

	xorVal := iv
	buf := make([]byte, blockSize)
	for i := 0; i < len(ciphertext); i += blockSize {
		block.Decrypt(buf, ciphertext[i:i+blockSize])
		t, err := xor(buf, xorVal)
		if err != nil {
			return nil, err
		}
		copy(plaintext[i:i+blockSize], t)
		xorVal = ciphertext[i : i+blockSize]

	}

	return plaintext, nil
}

// Challenge10 - Implement CBC mode
func Challenge10(plaintext, key, iv []byte) ([]byte, error) {
	return cbcEncrypt(plaintext, key, iv)
}
