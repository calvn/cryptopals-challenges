package cryptopals

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"math/big"
	mathrand "math/rand"
)

func pad(block []byte, length int) []byte {
	// remainder = k - (l mod k)
	remainder := length - (len(block) % length)

	result := make([]byte, len(block)+remainder)
	copy(result, block)

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

func ecbEncrypt(plaintext, key []byte) ([]byte, error) {
	// ECB - No IV
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(plaintext)%blockSize != 0 {
		return nil, fmt.Errorf("error decrypting: ciphertext length needs to ba a multiple of the blocksize")
	}

	ciphertext := make([]byte, len(plaintext))

	for i := 0; i < len(plaintext); i += blockSize {
		block.Encrypt(ciphertext[i:i+blockSize], plaintext[i:i+blockSize])
	}

	return ciphertext, nil
}

func encryptionOracle(in []byte) ([]byte, error) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("error generating key: %v", err)
	}

	prefix := make([]byte, mathrand.Intn(6)+5)
	suffix := make([]byte, mathrand.Intn(6)+5)
	_, err = rand.Read(prefix)
	if err != nil {
		return nil, fmt.Errorf("error generating prefix: %v", err)
	}
	_, err = rand.Read(suffix)
	if err != nil {
		return nil, fmt.Errorf("error generating suffix: %v", err)
	}

	plaintext := append(prefix, append(in, suffix...)...)
	plaintext = pad(plaintext, 16)

	// Encrypt with CBC or EBC
	var result []byte
	choice, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return nil, fmt.Errorf("error generating crypto/rand int: %v", err)
	}
	if choice.Cmp(big.NewInt(0)) == 0 {
		iv := make([]byte, 16)
		_, err := rand.Read(iv)
		if err != nil {
			return nil, fmt.Errorf("error generating iv: %v", err)
		}
		result, err = cbcEncrypt(plaintext, key, iv)
		if err != nil {
			return nil, err
		}
	} else {
		result, err = ecbEncrypt(plaintext, key)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// Challenge11 - An ECB/CBC detection oracle
func Challenge11() (int, int, error) {
	ecbCount, cbcCount := 0, 0
	in := []byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE")
	for i := 0; i < 100; i++ {
		ciphertext, err := encryptionOracle(in)
		if err != nil {
			return 0, 0, err
		}

		isECB, err := detectECB(ciphertext, 16)
		if err != nil {
			return 0, 0, err
		}

		if isECB {
			ecbCount++
		} else {
			cbcCount++
		}
	}

	return ecbCount, cbcCount, nil
}
