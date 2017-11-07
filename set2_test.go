package cryptopals

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"log"
	"testing"
)

func TestSet2_Challenge9(t *testing.T) {
	actual, err := Challenge9([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	if !bytes.Equal(actual, expected) {
		t.Fatalf("mismatch:\nactual:%v\nexpected:%v", actual, expected)
	}
}

func TestSet2_Challenge10(t *testing.T) {
	// Test cbcDecrypt
	input, err := ioutil.ReadFile("testdata/set2_challenge10.txt")
	if err != nil {
		t.Fatal(err)
	}

	data, err := base64.StdEncoding.DecodeString(string(input))
	if err != nil {
		t.Fatal(err)
	}

	iv := make([]byte, 16)
	key := []byte("YELLOW SUBMARINE")

	plaintext, err := cbcDecrypt(data, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("%s", plaintext)

	// Test challenge
	ciphertext, err := Challenge10(plaintext, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(ciphertext, data) {
		t.Fatalf("mistmatch:\nactual:%v\nexpected:%v", ciphertext, data)
	}
}

func TestSet2_Challenge11(t *testing.T) {
	ecb, cbc, err := Challenge11()
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("ecb count: %d, cbc count: %d", ecb, cbc)
}
