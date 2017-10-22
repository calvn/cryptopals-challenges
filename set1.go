package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
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

	var maxScore = 0.0
	var lastRes = []byte{}
	for i := 0; i <= 255; i++ {
		res := singleCharXOR(decodedInput, byte(i))
		s := determineScore(res, table)
		if s > maxScore {
			maxScore = s
			// maxIndex = i
			lastRes = res
		}
	}

	return string(lastRes), nil
}

// singleCharXOR performs XOR against a []byte slice using a single byte
func singleCharXOR(in []byte, c byte) []byte {
	res := make([]byte, len(in))
	for i, char := range in {
		res[i] = char ^ c
	}

	return res
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
