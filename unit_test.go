package unknownaccess_test

import (
	"bytes"
	"testing"
	"unknownaccess"
)

func TestEncryptDecrypt1Secret(t *testing.T) {
	block := unknownaccess.NewBlock()

	secret1 := []byte("This is secret number 1.")

	if err := block.Encrypt("password1", secret1); err != nil {
		panic(err)
	}

	marshaled, err := block.Marshal()
	if err != nil {
		panic(err)
	}

	b2, err := unknownaccess.Unmarshal(marshaled)
	if err != nil {
		panic(err)
	}

	data, err := b2.Decrypt("password1")
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(secret1, data) {
		t.Fatal("secrets do not match")
	}
}
