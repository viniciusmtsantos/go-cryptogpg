package gpgutils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/helper"
)

var decryptedFile *os.File

func DecryptMessageArmored(key, fileIn, passphrase, fileOut string) error {
	keyFile, err := os.Open(key)
	if err != nil {
		fmt.Printf("failed reading file: %s", err)
		return err
	}
	defer keyFile.Close()

	keyBytesContent, err := io.ReadAll(keyFile)
	if err != nil {
		return err
	}
	keyStringContent := string(keyBytesContent)

	fileToEncrypt, err := os.Open(fileIn)
	if err != nil {
		fmt.Printf("failed reading file: %s", err)
		return err
	}
	defer fileToEncrypt.Close()

	fileBytesContent, err := io.ReadAll(fileToEncrypt)
	if err != nil {
		return err
	}
	fileStringContent := string(fileBytesContent)

	armor, err := helper.DecryptMessageArmored(keyStringContent, []byte(passphrase), fileStringContent)
	if err != nil {
		return err
	}

	if fileOut == "" {
		fileOut = filepath.Join(filepath.Dir(fileOut), "decript_"+strings.TrimSuffix(filepath.Base(fileIn), filepath.Ext(fileIn)))
	}

	decryptedFile, err = os.Create(fileOut)
	if err != nil {
		return err
	}
	defer decryptedFile.Close()

	_, err = decryptedFile.Write([]byte(armor))
	if err != nil {
		return err
	}

	fmt.Println("Arquivo descriptografado com sucesso!")

	return nil
}

func DecryptVerifyMessageArmored(pubkey, privkey, passphrase, fileIn, fileOut string) error {
	pubKeyFile, err := os.Open(pubkey)
	if err != nil {
		fmt.Printf("failed reading file: %s", err)
		return err
	}
	defer pubKeyFile.Close()

	pubKeyBytesContent, err := io.ReadAll(pubKeyFile)
	if err != nil {
		return err
	}
	pubKeyStringContent := string(pubKeyBytesContent)

	privKeyFile, err := os.Open(privkey)
	if err != nil {
		fmt.Printf("failed reading file: %s", err)
		return err
	}
	defer privKeyFile.Close()

	keyBytesContent, err := io.ReadAll(privKeyFile)
	if err != nil {
		return err
	}
	privKeyStringContent := string(keyBytesContent)

	fileToEncrypt, err := os.Open(fileIn)
	if err != nil {
		fmt.Printf("failed reading file: %s", err)
		return err
	}
	defer fileToEncrypt.Close()

	fileBytesContent, err := io.ReadAll(fileToEncrypt)
	if err != nil {
		return err
	}
	fileStringContent := string(fileBytesContent)

	armor, err := helper.DecryptVerifyMessageArmored(pubKeyStringContent, privKeyStringContent, []byte(passphrase), fileStringContent)
	if err != nil {
		return err
	}

	if fileOut == "" {
		fileOut = filepath.Join(filepath.Dir(fileOut), "decript_"+strings.TrimSuffix(filepath.Base(fileIn), filepath.Ext(fileIn)))
	}

	decryptedFile, err = os.Create(fileOut)
	if err != nil {
		return err
	}
	defer decryptedFile.Close()

	_, err = decryptedFile.Write([]byte(armor))
	if err != nil {
		return err
	}

	fmt.Println("Arquivo descriptografado com sucesso!")

	return nil
}
