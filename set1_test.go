package cryptopals

import (
	"bytes"
	"io/ioutil"
	"strings"
	"testing"
)

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
	data, err := ioutil.ReadFile("testdata/pride_prejudice.txt")
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
}
