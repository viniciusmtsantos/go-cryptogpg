package gpgutils

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func DecFile(fileToDecrypt, secretKeyring, fileOutputDir string) {
	encryptedFile, err := os.Open(fileToDecrypt)
	if err != nil {
		fmt.Println("Erro ao abrir o arquivo de entrada:", err)
	}
	defer encryptedFile.Close()

	privateKeyASC, err := os.Open(secretKeyring)
	if err != nil {
		fmt.Println(err)
	}
	defer privateKeyASC.Close()

	readArmored, err := openpgp.ReadArmoredKeyRing(privateKeyASC)
	if err != nil {
		fmt.Println("Erro ao ler a chave privada do destinatário:", err)
	}

	decryptedWriter, err := armor.Decode(encryptedFile)
	if err != nil {
		fmt.Println("Erro ao criar o escritor de texto criptografado:", err)
	}

	// Verificar a passphrase
	for _, entity := range readArmored {
		err := entity.PrivateKey.Decrypt([]byte("teste123"))
		if err != nil {
			fmt.Println("Falha na verificação da passphrase:", err)
			return
		}
	}

	decryptedMessage, err := openpgp.ReadMessage(decryptedWriter.Body, readArmored, nil, nil)
	if err != nil {
		fmt.Println("Erro ao descriptografar a mensagem:", err)
	}

	decryptedFile, err := os.Create(filepath.Join(fileOutputDir, "decrypted.txt"))
	if err != nil {
		fmt.Println("Erro ao criar o arquivo de saída:", err)
	}
	defer decryptedFile.Close()

	_, err = io.Copy(decryptedFile, decryptedMessage.UnverifiedBody)
	if err != nil {
		log.Fatal(err)
	}

	// decryptedBytes, err := io.ReadAll(decryptedMessage.UnverifiedBody)
	// if err != nil {
	// 	fmt.Println("Erro ao ler a mensagem descriptografada:", err)
	// }

	// fmt.Print(string(decryptedBytes))

	// _, err = decryptedFile.Write(decryptedBytes)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	fmt.Println("Arquivo descriptografado com sucesso!")
}

func DecryptFile(publicKeyring, secretKeyring string, inputFile, outputFile string, bits int) error {
	// pubKey := DecodePublicKey(publicKeyring)
	// privKey := DecodePrivateKey(secretKeyring)

	// entity := CreateEntityFromKeys(pubKey, privKey, bits)

	input, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("Error opening input file: %s", err)
	}
	defer input.Close()

	output, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("Error creating output file: %s", err)
	}
	defer output.Close()

	block, err := armor.Decode(input)
	if err != nil {
		return fmt.Errorf("Error reading OpenPGP Armor: %s", err)
	}

	if block.Type != "Message" {
		return fmt.Errorf("Invalid message type")
	}

	var entityList openpgp.EntityList
	// entityList = append(entityList, entity)

	md, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	if err != nil {
		return fmt.Errorf("Error reading message: %s", err)
	}

	compressed, err := gzip.NewReader(md.UnverifiedBody)
	if err != nil {
		return fmt.Errorf("Invalid compression level: %s", err)
	}
	defer compressed.Close()

	n, err := io.Copy(output, compressed)
	if err != nil {
		return fmt.Errorf("Error reading encrypted file: %s", err)
	}

	fmt.Printf("Decrypted %d bytes\n", n)
	return nil
}

func DecMessage(encryptedMessage *bytes.Buffer) error {
	privateKeyASC, err := os.Open("D:/OneDrive - Riversoft Integração e Desenvolvimento de Software Ltda/Documentos/Desenv/riversoft/stcpgpg/keys/Vinicius Matheus Santos_0x28352859_SECRET.asc")
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer privateKeyASC.Close()

	readArmoredKey, err := openpgp.ReadArmoredKeyRing(privateKeyASC)
	if err != nil {
		fmt.Println("Erro ao ler a chave privada do destinatário:", err)
		return nil
	}

	decryptedMessage, err := openpgp.ReadMessage(encryptedMessage, readArmoredKey, nil, nil)
	if err != nil {
		fmt.Println("Erro ao descriptografar a mensagem:", err)
		return nil
	}

	decryptedBytes, err := io.ReadAll(decryptedMessage.UnverifiedBody)
	if err != nil {
		fmt.Println("Erro ao ler a mensagem descriptografada:", err)
		return nil
	}

	fmt.Println("Mensagem descript:", string(decryptedBytes))
	return nil
}

func DecTest(encString, secretKeyring string) (string, error) {
	fmt.Println("Secret Keyring:", secretKeyring)
	// fmt.Println("Passphrase:", passphrase)

	// init some vars
	// var entity *openpgp.Entity
	var entityList openpgp.EntityList

	// Open the private key file
	keyringFileBuffer, err := os.Open(secretKeyring)
	if err != nil {
		return "", err
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadArmoredKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}
	// entity = entityList[0]

	// Get the passphrase and read the private key.
	// Have not touched the encrypted string yet
	// passphraseByte := []byte(passphrase)
	// fmt.Println("Decrypting private key using passphrase")
	// entity.PrivateKey.Decrypt(passphraseByte)
	// for _, subkey := range entity.Subkeys {
	// 	subkey.PrivateKey.Decrypt(passphraseByte)
	// }
	// fmt.Println("Finished decrypting private key using passphrase")

	// Decode the base64 string
	dec, err := base64.StdEncoding.DecodeString(encString)
	if err != nil {
		return "", err
	}

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
	if err != nil {
		return "", err
	}
	bytes, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decStr := string(bytes)

	log.Println("Decrypted Secret:", decStr)

	return decStr, nil
}
