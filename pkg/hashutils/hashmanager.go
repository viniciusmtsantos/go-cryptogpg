package hashutils

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func OpenAndCompareHashFiles(originalFile, decryptedFile string) {
	originalHash, err := os.Open(originalFile)
	if err != nil {
		fmt.Printf("failed reading file: %s", err)
		return
	}
	defer originalHash.Close()

	decryptedHash, err := os.Open(decryptedFile)
	if err != nil {
		fmt.Printf("failed reading file: %s", err)
		return
	}
	defer decryptedHash.Close()

	hashOriString, err := CalcularHash(originalHash)
	if err != nil {
		fmt.Printf("failed calculating hash for original file: %s", err)
		return
	}

	hashDecString, err := CalcularHash(decryptedHash)
	if err != nil {
		fmt.Printf("failed calculating hash for decrypted file: %s", err)
		return
	}

	match := subtle.ConstantTimeCompare([]byte(hashOriString), []byte(hashDecString)) == 1

	if match {
		fmt.Println("Os hashes correspondem.")
	} else {
		fmt.Println("Os hashes não correspondem.")
	}
}

func CalcularHash(fileToEncrypt io.Reader) (string, error) {
	// hash := sha256.Sum256(dados)
	// return fmt.Sprintf("%x", hash)

	hash := sha256.New()

	if _, err := io.Copy(hash, fileToEncrypt); err != nil {
		return "", err
	}

	hashValue := hash.Sum(nil)

	hashString := hex.EncodeToString(hashValue)

	fmt.Println(hashString)

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
