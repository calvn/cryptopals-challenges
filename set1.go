package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/bits"
)

// Challenge1 - Convert hex to base64.
func Challenge1(input string) (string, error) {
	rawHex, err := hex.DecodeString(input)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(rawHex), nil
}

func xor(first, second []byte) ([]byte, error) {
	// Check length equality
	if len(first) != len(second) {
		return nil, fmt.Errorf("input legnths do not match")
	}

	// Perform XOR
	result := make([]byte, len(first))
	for i := range first {
		result[i] = first[i] ^ second[i]
	}

	return result, nil
}

// Challenge2 - Fixed XOR.
func Challenge2(first, second string) ([]byte, error) {
	// Decode inputs from strings
	rawFirst, err := hex.DecodeString(first)
	if err != nil {
		return nil, err
	}

	rawSecond, err := hex.DecodeString(second)
	if err != nil {
		return nil, err
	}

	s, err := xor(rawFirst, rawSecond)
	if err != nil {
		return nil, err
	}

	// Encode back to hex
	res := make([]byte, hex.EncodedLen(len(s)))
	hex.Encode(res, s)

	return res, nil
}

// Challenge3 - Single-byte XOR cipher
func Challenge3(in string, table map[byte]float64) (string, error) {
	decodedInput, err := hex.DecodeString(in)
	if err != nil {
		return "", err
	}

	res, _, _ := findSigleCharXORKey(decodedInput, table)

	return string(res), nil
}

// singleCharXOR performs XOR against a []byte slice using a single byte
func singleCharXOR(in []byte, c byte) []byte {
	res := make([]byte, len(in))
	for i, char := range in {
		res[i] = char ^ c
	}

	return res
}

// findSigleCharXORKey finds the single char key that is used to encode
// in []byte slice, based on the provided scoring table.
func findSigleCharXORKey(in []byte, table map[byte]float64) ([]byte, byte, float64) {
	var maxScore = 0.0
	var lastRes = []byte{}
	var key byte

	for i := 0; i <= 255; i++ {
		res := singleCharXOR(in, byte(i))
		s := determineScore(res, table)
		if s > maxScore {
			maxScore = s
			lastRes = res
			key = byte(i)
		}
	}

	return lastRes, key, maxScore
}

// scoreMapFromSample builds a scoring table based on provided input data
// (plaintext file).
func buildScoringTable(data []byte) map[byte]float64 {
	// Count occurence
	occurenceScores := make(map[byte]float64)
	for _, b := range data {
		occurenceScores[b]++
	}

	// Determine score for each occurence
	for char, count := range occurenceScores {
		occurenceScores[char] = count / float64(len(data))
	}

	return occurenceScores
}

// determineScore computes the overall score from some input
// based on a provided scoring table map.
func determineScore(in []byte, table map[byte]float64) float64 {
	var total float64
	for _, c := range in {
		total += table[c]
	}

	return total / float64(len(in))
}

// Challenge4 - Detect single-character XOR
func Challenge4(in []byte, table map[byte]float64) (string, error) {
	var maxScore = 0.0
	var lastRes = []byte{}

	for _, line := range bytes.Split(in, []byte("\n")) {
		decodedInput, err := hex.DecodeString(string(line))
		if err != nil {
			return "", err
		}

		res, _, score := findSigleCharXORKey(decodedInput, table)
		if score > maxScore {
			maxScore = score
			lastRes = res
		}
	}

	return string(lastRes), nil
}

// Challenge5 - Implement repeating-key XOR
func Challenge5(in []byte, key []byte) ([]byte, error) {
	res := make([]byte, len(in))
	res = repeatingKeyXOR(in, key)

	return res, nil
}

// repeatingKeyXOR returns the repeating XOR'ed byte slice using
// the provided key.
func repeatingKeyXOR(in []byte, key []byte) []byte {
	mod := len(key)
	res := make([]byte, len(in))
	for i, char := range in {
		res[i] = char ^ key[i%mod]
	}

	result := make([]byte, hex.EncodedLen(len(res)))
	hex.Encode(result, []byte(res))

	return res
}

// Challenge6 - Break repeating-key XOR
func Challenge6(in []byte, table map[byte]float64) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(string(in))
	if err != nil {
		return nil, err
	}

	minDistance := 10000.0
	keyLen := 0
	// Part 1-4: Determine min keysize, store as keyLen
	for keysize := 2; keysize <= 40; keysize++ {
		first := data[:keysize*4]
		second := data[keysize*4 : keysize*4*2]

		distance1, err := hammingDistance(first, second)
		if err != nil {
			return nil, err
		}

		third := data[keysize*4*2 : keysize*4*3]
		fourth := data[keysize*4*3 : keysize*4*4]

		distance2, err := hammingDistance(third, fourth)
		if err != nil {
			return nil, err
		}

		distance := float64((distance1 + distance2) / 2)

		var normalized float64
		normalized = distance / float64(keysize)

		if normalized < minDistance {
			minDistance = normalized
			keyLen = keysize
		}
	}

	// Part 5: Split data into blocks of keyLen
	var blocks [][]byte
	for i := range data {
		if i%keyLen == 0 {
			block := make([]byte, keyLen)
			block = data[i : i+keyLen]
			blocks = append(blocks, block)
		}
	}

	// Part 6: Transpose
	var transposedBlocks [][]byte
	// Build matrix
	for _ = range blocks {
		transposedBlock := make([]byte, len(blocks))
		transposedBlocks = append(transposedBlocks, transposedBlock)
	}

	// Transpose
	for i, block := range blocks {
		for j, c := range block {
			transposedBlocks[j][i] = c
		}
	}

	// Part 7-8: Solve
	var combined []byte
	for _, b := range transposedBlocks {
		_, key, _ := findSigleCharXORKey(b, table)
		combined = append(combined, key)
	}

	return combined, nil
}

func hammingDistance(first, second []byte) (int, error) {
	distance := 0

	if len(first) != len(second) {
		return 0, fmt.Errorf("provided slices are not of equal lengths: first: %d, second %d", len(first), len(second))
	}

	for i := range first {
		distance += bits.OnesCount8(first[i] ^ second[i])
	}

	return distance, nil
}

func ecbDecrypt(ciphertext, key []byte) ([]byte, error) {
	// ECB - No IV
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("error decrypting: ciphertext length needs to ba a multiple of the blocksize")
	}

	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += blockSize {
		block.Decrypt(plaintext[i:i+blockSize], ciphertext[i:i+blockSize])
	}

	return plaintext, nil
}

// Challenge7 - AES in ECB mode
func Challenge7(in []byte, key []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(string(in))
	if err != nil {
		return nil, err
	}

	return ecbDecrypt(ciphertext, key)
}

// detectECB looks for the following condition: identical plaintext blocks are
// encrypted into identical ciphertext blocks
func detectECB(ciphertext []byte, blockSize int) (bool, error) {
	if len(ciphertext)%blockSize != 0 {
		return false, fmt.Errorf("error detecting ECB: ciphertext length needs to ba a multiple of the blocksize")
	}

	visited := make(map[string]bool)
	for i := 0; i < len(ciphertext); i += blockSize {
		current := string(ciphertext[i : i+blockSize])
		if visited[current] == true {
			return true, nil
		}
		visited[current] = true
	}

	return false, nil
}

// Challenge8 - Detect AES in ECB mode
func Challenge8(in []byte) ([]byte, error) {
	// Read each line
	for _, line := range bytes.Split(in, []byte("\n")) {
		decodedInput, err := hex.DecodeString(string(line))
		if err != nil {
			return nil, err
		}

		isECB, err := detectECB(decodedInput, 16)
		if err != nil {
			return nil, err
		}
		if isECB {
			return line, nil
		}
	}

	return nil, fmt.Errorf("no ECB encrypted ciphertext found")
}
