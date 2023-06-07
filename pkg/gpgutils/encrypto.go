package gpgutils

import (
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/gopenpgp/v2/helper"
)

var encryptedFile *os.File

func EncryptMessageArmored(key, fileIn, fileOut string) error {
	if _, err := os.Stat(key); os.IsNotExist(err) {
		return fmt.Errorf("chave pública não encontrada")
	}

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

	// fileStringContent := string(fileBytesContent)

	// armor, err := helper.EncryptMessageArmored(keyStringContent, fileStringContent)
	// if err != nil {
	// 	return err
	// }

	armor, err := helper.EncryptBinaryMessageArmored(keyStringContent, fileBytesContent)
	if err != nil {
		return err
	}

	if fileOut == "" {
		encryptedFile, err = os.Create(fileIn + ".gpg")
		if err != nil {
			return err
		}
	} else {
		encryptedFile, err = os.Create(fileOut)
		if err != nil {
			return err
		}
	}
	defer encryptedFile.Close()

	_, err = encryptedFile.Write([]byte(armor))
	if err != nil {
		return err
	}

	fmt.Println("Arquivo criptografado com sucesso!")

	return nil
}

func EncryptSignMessageArmored(pubkey, privkey, passphrase, fileIn, fileOut string) error {
	if _, err := os.Stat(pubkey); os.IsNotExist(err) {
		return fmt.Errorf("chave pública não encontrada")
	}

	if _, err := os.Stat(privkey); os.IsNotExist(err) {
		return fmt.Errorf("chave privada não encontrada")
	}

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

	armor, err := helper.EncryptSignMessageArmored(pubKeyStringContent, privKeyStringContent, []byte(passphrase), fileStringContent)
	if err != nil {
		return err
	}

	if fileOut == "" {
		encryptedFile, err = os.Create(fileIn + ".gpg")
		if err != nil {
			return err
		}
	} else {
		encryptedFile, err = os.Create(fileOut + ".gpg")
		if err != nil {
			return err
		}
	}
	defer encryptedFile.Close()

	_, err = encryptedFile.Write([]byte(armor))
	if err != nil {
		return err
	}

	fmt.Println("Arquivo criptografado com sucesso!")
	return nil
}
