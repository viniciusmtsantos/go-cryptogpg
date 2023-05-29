package hashutils

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func CalcularHash(fileToEncrypt io.Reader) (string, error) {
	// hash := sha256.Sum256(dados)
	// return fmt.Sprintf("%x", hash)

	hash := sha256.New()

	if _, err := io.Copy(hash, fileToEncrypt); err != nil {
		return "", err
	}

	hashValue := hash.Sum(nil)

	hashString := hex.EncodeToString(hashValue)

	return hashString, nil
}

func CompararHashes(fileToEncrypt *os.File, hashOriginal string) {
	hashPosCalculado, _ := CalcularHash(fileToEncrypt)

	match := subtle.ConstantTimeCompare([]byte(hashOriginal), []byte(hashPosCalculado)) == 1

	if match {
		fmt.Println("Os hashes correspondem.")
	} else {
		fmt.Println("Os hashes não correspondem.")
	}
}
