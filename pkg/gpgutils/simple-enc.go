package gpgutils

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/ProtonMail/gopenpgp/v2/helper"
)

func EncryptMessageArmored(key, filePath string) error {
	// Lê o conteúdo do arquivo
	keyBytesContent, err := ioutil.ReadFile(key)
	if err != nil {
		fmt.Println("Erro ao ler o arquivo:", err)
		return err
	}
	keyStringContent := string(keyBytesContent)

	// Lê o conteúdo do arquivo
	fileBytesContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("Erro ao ler o arquivo:", err)
		return err
	}
	fileStringContent := string(fileBytesContent)

	armor, err := helper.EncryptMessageArmored(keyStringContent, fileStringContent)
	if err != nil {
		return err
	}

	// armor, err := helper.EncryptBinaryMessageArmored(keyStringContent, fileBytesContent)
	// if err != nil {
	// 	return err
	// }

	// Escrita da chave pública em um arquivo
	publicKeyFile, err := os.Create(filePath + ".gpg")
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	_, err = publicKeyFile.Write([]byte(armor))
	if err != nil {
		return err
	}

	fmt.Println("Tá Encriptado fi")

	return nil
}

func EncryptSignMessageArmored(pubkey, privkey, passphrase, filePath string) error {
	pubKeyBytesContent, err := ioutil.ReadFile(pubkey)
	if err != nil {
		fmt.Println("Erro ao ler o arquivo:", err)
		return err
	}
	pubKeyStringContent := string(pubKeyBytesContent)

	privKeyBytesContent, err := ioutil.ReadFile(privkey)
	if err != nil {
		fmt.Println("Erro ao ler o arquivo:", err)
		return err
	}
	privKeyStringContent := string(privKeyBytesContent)

	fileBytesContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("Erro ao ler o arquivo:", err)
		return err
	}
	fileStringContent := string(fileBytesContent)

	armor, err := helper.EncryptSignMessageArmored(pubKeyStringContent, privKeyStringContent, []byte(passphrase), fileStringContent)
	if err != nil {
		return err
	}

	// Escrita da chave pública em um arquivo
	publicKeyFile, err := os.Create(filePath + ".gpg")
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	_, err = publicKeyFile.Write([]byte(armor))
	if err != nil {
		return err
	}

	return nil
}
