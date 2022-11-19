package unknownaccess

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	dataSize = 140

	authTagSize = 16
)

var (
	ErrFailDecrypt = errors.New("failed to decrypt block")
	ErrDataFull    = errors.New("all data blocks full")
)

type Block struct {
	IV   [12]byte          //12 bytes
	Data [3][dataSize]byte // (124bytes content + 16bytes tag)*3 bytes
}

type Offset uint16

func NewBlock() *Block {
	b := &Block{}
	rand.Read(b.IV[:])

	return b
}

func (b *Block) SetS1(passphrase string, data []byte) error {
	return b.setSecret(1, passphrase, data)
}

func (b *Block) SetS2(passphrase string, data []byte) error {
	return b.setSecret(2, passphrase, data)
}

func (b *Block) SetS3(passphrase string, data []byte) error {
	return b.setSecret(3, passphrase, data)
}

func (b *Block) setSecret(position uint8, passphrase string, data []byte) error {

	nonce, err := b.iv(position)
	if err != nil {
		return err
	}

	enc, err := b.newCipher(passphrase, nonce)
	if err != nil {
		return err
	}

	// compute PKCS#5 padding
	padding := pkcs5(len(data), dataSize-authTagSize)

	// use generated IV and cipher to encrypt data and place into block
	ciphertext := enc.Seal(nil, nonce, append(data, padding...), nil)

	// write ciphertext to block
	copy(b.Data[position-1][:], ciphertext)

	return nil
}

func (b *Block) newCipher(passphrase string, nonce []byte) (cipher.AEAD, error) {
	// Run passphrase through Argon2Key KDF with default settings to
	// generate a 256bit key
	k := argon2.Key([]byte(passphrase), nonce, 3, 32*1024, 4, 32)

	cipherAES, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	// create new GCM cipher
	return cipher.NewGCM(cipherAES)
}

func (b *Block) iv(position uint8) ([]byte, error) {
	ivKDF := hkdf.New(sha256.New, b.IV[:], nil, nil)
	iv := make([]byte, 12)

	// derive IV for corresponding location
	for i := 0; i <= int(position); i++ {
		n, err := ivKDF.Read(iv)
		if err != nil {
			return nil, err
		} else if n < 12 {
			return nil, io.ErrShortWrite
		}
	}

	return iv, nil
}

// Decrypt will find your secret within the block and decrypt it
func (b *Block) Decrypt(passphrase string) ([]byte, error) {

	// attempt to decrypt each block one by one until successful
	for i := uint8(1); i <= 3; i++ {
		data, err := b.decryptSecret(i, passphrase)
		if err == nil {
			return data, nil
		}
	}

	return nil, ErrFailDecrypt
}

func (b *Block) decryptSecret(position uint8, passphrase string) ([]byte, error) {

	nonce, err := b.iv(position)
	if err != nil {
		return nil, err
	}

	enc, err := b.newCipher(passphrase, nonce)
	if err != nil {
		return nil, err
	}

	plaintext, err := enc.Open(nil, nonce, b.Data[position-1][:], nil)
	if err != nil {
		return nil, err
	}

	return pkcs5Unmarshal(plaintext), nil
}

func (b *Block) WriteDecoys() error {

	indexes := b.unusedDataIndexes()

	for _, p := range indexes {
		n, err := rand.Read(b.Data[p][:])
		if err != nil {
			return err
		} else if n != dataSize {
			return io.ErrShortWrite
		}
	}

	return nil
}

// Encrypt will randomly position your secret within the block and encrypt it
func (b *Block) Encrypt(passphrase string, data []byte) error {
	freeIndexes := b.unusedDataIndexes()

	if len(freeIndexes) == 0 {
		return ErrDataFull
	}

	// pick random index from list
	indexReference, err := rand.Int(rand.Reader, big.NewInt(int64(len(freeIndexes))))
	if err != nil {
		return err
	}

	index := freeIndexes[indexReference.Int64()]

	return b.setSecret(uint8(index)+1, passphrase, data)
}

func (b *Block) unusedDataIndexes() (indexList []int) {
	// create a blank array to compare to data blocks
	blank := make([]byte, dataSize)

	// check each data block and see which ones are all zeros
	for i := 0; i < 3; i++ {
		if bytes.Equal(b.Data[i][:], blank) {
			indexList = append(indexList, i)
		}
	}

	return indexList
}

// Encode will encode the block to a byte format
func (b *Block) Marshal() ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	_, err := b.Encode(buf)
	return buf.Bytes(), err
}

// Encode will encode the block to a byte format
func (b *Block) Encode(w io.Writer) (n int, err error) {
	if err = b.WriteDecoys(); err != nil {
		return 0, err
	}

	written, err := w.Write(b.IV[:])
	n += written
	if err != nil {
		return n, err
	} else if n < 12 {
		return n, io.ErrShortWrite
	}

	// write data blocks
	for i := 0; i < 3; i++ {
		written, err = w.Write(b.Data[i][:])
		n += written
		if err != nil {
			return n, err
		} else if n < dataSize {
			return n, io.ErrShortWrite
		}
	}

	return n, nil
}

// Unmarshal will read the block and import it to a type
func Unmarshal(block []byte) (*Block, error) {
	buf := bytes.NewBuffer(block)

	return Decode(buf)
}

// Decode will read the block and import it to a type
func Decode(r io.Reader) (*Block, error) {
	b := &Block{}

	n, err := r.Read(b.IV[:])
	if err != nil {
		return nil, err
	} else if n < 12 {
		return nil, io.ErrUnexpectedEOF
	}

	// read data blocks
	for i := 0; i < 3; i++ {
		n, err = r.Read(b.Data[i][:])
		if err != nil {
			return nil, err
		} else if n < dataSize {
			return nil, io.ErrUnexpectedEOF
		}
	}

	return b, nil
}
