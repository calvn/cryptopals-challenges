package cryptopals

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
