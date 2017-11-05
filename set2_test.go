package cryptopals

import (
	"bytes"
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
