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

func TestEncryptDecrypt2Secrets(t *testing.T) {
	block := unknownaccess.NewBlock()

	secret1 := []byte("This is secret number 1.")
	secret2 := []byte("This is secret number 2.")

	if err := block.Encrypt("password1", secret1); err != nil {
		if err := block.Encrypt("password2", secret2); err != nil {
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

		data1, err := b2.Decrypt("password1")
		if err != nil {
			panic(err)
		}

		data2, err := b2.Decrypt("password2")
		if err != nil {
			panic(err)
		}

		if !bytes.Equal(secret1, data1) {
			t.Fatal("secrets do not match")
		}
		if !bytes.Equal(secret2, data2) {
			t.Fatal("secrets do not match")
		}
	}
}
