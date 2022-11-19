package main

import (
	"fmt"
	"unknownaccess"
)

func main() {
	block := unknownaccess.NewBlock()

	// encrypt a secret
	if err := block.Encrypt("my-secure-passphrase",
		[]byte("splice-dolphin-outpost-debate-galleria-lapping-dullness-stereo-enamel-rinse-twisted-comment"),
	); err != nil {
		panic(err)
	}

	// encrypt a decoy secret
	if err := block.Encrypt("different-secure-password",
		[]byte("anymore-pep-bacterium-embargo-reputably-groin-extrovert-harmony"),
	); err != nil {
		panic(err)
	}

	blockchunk, err := block.Marshal()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Blockchunk: %X\n", blockchunk)

	block2, err := unknownaccess.Unmarshal(blockchunk)
	if err != nil {
		panic(err)
	}

	// decrypt the decoy
	secret, err := block2.Decrypt("different-secure-password")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted Decoy: %s\n", secret)
}
