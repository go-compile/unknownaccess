package unknownaccess

//pkcs5 returns the padding buffer based on weather or not it is required
// Maximum blocksize is 255
func pkcs5(actual int, blockSize int) []byte {
	n := byte(blockSize - actual%blockSize)

	// create buf of len N full of bytes equal to value of N
	padding := make([]byte, n)
	for i := byte(0); i < n; i++ {
		padding[i] = n
	}

	return padding
}

//pkcs5Unmarshal removes padding
func pkcs5Unmarshal(buf []byte) []byte {
	l := len(buf)
	n := buf[l-1]
	return buf[:l-int(n)]
}
