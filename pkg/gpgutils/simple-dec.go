package gpgutils

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/ProtonMail/gopenpgp/v2/helper"
)

/////////////////////// DECRIPT /////////////////////////////////////

func DecryptMessageArmored(key, filePath, passphrase string) error {
	keyBytesContent, err := ioutil.ReadFile(key)
	if err != nil {
		fmt.Println("Erro ao ler o arquivo:", err)
		return err
	}
	keyStringContent := string(keyBytesContent)

	fileBytesContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("Erro ao ler o arquivo:", err)
		return err
	}
	fileStringContent := string(fileBytesContent)

	armor, err := helper.DecryptMessageArmored(keyStringContent, []byte(passphrase), fileStringContent)
	if err != nil {
		return err
	}

	// Escrita da chave pública em um arquivo
	publicKeyFile, err := os.Create(filepath.Join(filepath.Dir(filePath), "decriptado.txt"))
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	_, err = publicKeyFile.Write([]byte(armor))
	if err != nil {
		return err
	}

	fmt.Println("Decriptado fi")

	return nil
}

func DecryptVerifyMessageArmored(pubkey, privkey, passphrase, filePath string) error {
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

	armor, err := helper.DecryptVerifyMessageArmored(pubKeyStringContent, privKeyStringContent, []byte(passphrase), fileStringContent)
	if err != nil {
		return err
	}

	// Escrita da chave pública em um arquivo
	publicKeyFile, err := os.Create(filepath.Join(filepath.Dir(filePath), "decriptado.txt"))
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

/////////////////////// ENCRIPT /////////////////////////////////////
