package gpgutils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/helper"
)

func DecryptMessageArmored(key, filePath, passphrase string) error {
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

	fileToEncrypt, err := os.Open(filePath)
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

	// Escrita da chave pública em um arquivo
	decryptedFile, err := os.Create(filepath.Join(filepath.Dir(filePath), "decript_"+strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))))
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

func DecryptVerifyMessageArmored(pubkey, privkey, passphrase, filePath string) error {
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

	fileToEncrypt, err := os.Open(filePath)
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

	// Escrita da chave pública em um arquivo
	decryptedFile, err := os.Create(filepath.Join(filepath.Dir(filePath), "decriptado.txt"))
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
