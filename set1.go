package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Challenge1 is Convert hex to base64.
func Challenge1(input string) (string, error) {
	rawHex, err := hex.DecodeString(input)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(rawHex), nil
}

// Challenge2 is Fixed XOR.
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
