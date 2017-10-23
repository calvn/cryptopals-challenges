package cryptopals

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"strings"
	"testing"
)

const scoringPlaintextFile = "testdata/pride_and_prejudice.txt"

func TestSet1_Challenge1(t *testing.T) {
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	result, err := Challenge1("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Compare(expected, result) != 0 {
		t.Fatalf("expected: %s\ngot: %s\n", expected, result)
	}
}

func TestSet1_Challenge2(t *testing.T) {
	expected := []byte("746865206b696420646f6e277420706c6179")
	result, err := Challenge2("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(expected, result) != 0 {
		t.Fatalf("expected: %s\ngot: %s\n", expected, result)
	}
}

func TestSet1_Challenge3(t *testing.T) {
	// Read in the sample file
	data, err := ioutil.ReadFile(scoringPlaintextFile)
	if err != nil {
		t.Fatal(err)
	}

	scoringTable := buildScoringTable(data)

	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	output, err := Challenge3(input, scoringTable)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(output)

	// Check againt the hex-encoded output we "know" for sanity
	expected := []byte("436f6f6b696e67204d432773206c696b65206120706f756e64206f66206261636f6e")

	// Encode back to hex
	result := make([]byte, hex.EncodedLen(len(output)))
	hex.Encode(result, []byte(output))
	if bytes.Compare(expected, result) != 0 {
		t.Fatalf("expected: %s\ngot: %s\n", expected, result)
	}
}

func TestSet1_Challenge4(t *testing.T) {
	// Read in the sample file
	data, err := ioutil.ReadFile(scoringPlaintextFile)
	if err != nil {
		t.Fatal(err)
	}

	scoringTable := buildScoringTable(data)

	input, err := ioutil.ReadFile("testdata/set1_challenge4.txt")
	if err != nil {
		t.Fatal(err)
	}

	output, err := Challenge4(input, scoringTable)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(output)

	// Check againt the hex-encoded output we "know" for sanity
	expected := []byte("4e6f77207468617420746865207061727479206973206a756d70696e670a")

	// Encode back to hex
	result := make([]byte, hex.EncodedLen(len(output)))
	hex.Encode(result, []byte(output))
	if bytes.Compare(expected, result) != 0 {
		t.Fatalf("expected: %s\ngot: %s\n", expected, result)
	}
}

func TestSet1_Challenge5(t *testing.T) {
	input := []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)

	output, err := Challenge5(input, []byte("ICE"))
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

	result := make([]byte, hex.EncodedLen(len(output)))
	hex.Encode(result, []byte(output))
	if bytes.Compare(expected, result) != 0 {
		t.Fatalf("\nexpected: %s\ngot: %s\n", expected, result)
	}
}
