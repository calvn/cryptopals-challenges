package cryptopals

import (
	"bytes"
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

	// Check length equality
	if len(rawFirst) != len(rawSecond) {
		return nil, fmt.Errorf("input legnths do not match")
	}

	// Perform XOR
	s := make([]byte, len(rawFirst))
	for i := range rawFirst {
		s[i] = rawFirst[i] ^ rawSecond[i]
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
func Challenge6(in []byte) error {
	_, err := base64.StdEncoding.DecodeString(string(in))
	if err != nil {
		return err
	}

	return nil
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
