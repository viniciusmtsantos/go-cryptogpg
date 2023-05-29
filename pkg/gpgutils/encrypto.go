package gpgutils

import (
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/gopenpgp/v2/helper"
)

func EncryptMessageArmored(key, filePath string) error {
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

	// fileStringContent := string(fileBytesContent)

	// armor, err := helper.EncryptMessageArmored(keyStringContent, fileStringContent)
	// if err != nil {
	// 	return err
	// }

	armor, err := helper.EncryptBinaryMessageArmored(keyStringContent, fileBytesContent)
	if err != nil {
		return err
	}

	// Escrita da chave pública em um arquivo
	encryptedFile, err := os.Create(filePath + ".gpg")
	if err != nil {
		return err
	}
	defer encryptedFile.Close()

	_, err = encryptedFile.Write([]byte(armor))
	if err != nil {
		return err
	}

	fmt.Println("Arquivo criptografado com sucesso!")

	return nil
}

func EncryptSignMessageArmored(pubkey, privkey, passphrase, filePath string) error {
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

	armor, err := helper.EncryptSignMessageArmored(pubKeyStringContent, privKeyStringContent, []byte(passphrase), fileStringContent)
	if err != nil {
		return err
	}

	// Escrita da chave pública em um arquivo
	encryptedFile, err := os.Create(filePath + ".gpg")
	if err != nil {
		return err
	}
	defer encryptedFile.Close()

	_, err = encryptedFile.Write([]byte(armor))
	if err != nil {
		return err
	}

	fmt.Println("Arquivo criptografado com sucesso!")
	return nil
}
