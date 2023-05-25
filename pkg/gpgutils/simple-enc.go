package gpgutils

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func EncFile(fileToEncrypt, publicKeyring, fileOutputDir string) {
	fileToEnc, err := os.Open(fileToEncrypt)
	if err != nil {
		fmt.Println("Erro ao abrir o arquivo de entrada:", err)
		return
	}
	defer fileToEnc.Close()

	// Ler a chave pública do destinatário
	publicKeyASC, err := os.Open(publicKeyring)
	if err != nil {
		fmt.Println("Erro ao abrir a chave pública do destinatário:", err)
		return
	}
	defer publicKeyASC.Close()

	// Ler o conteúdo do arquivo original
	var fileContent bytes.Buffer
	_, err = io.Copy(&fileContent, fileToEnc)
	if err != nil {
		fmt.Println("Erro ao ler o conteúdo do arquivo de entrada:", err)
		return
	}

	// Criar o arquivo criptografado
	encryptedFile, err := os.Create(filepath.Join(fileOutputDir, "encrypted.gpg"))
	if err != nil {
		fmt.Println("Erro ao criar o arquivo de saída:", err)
		return
	}
	defer encryptedFile.Close()

	// Criar o escritor de texto criptografado
	encryptedWriter, err := armor.Encode(encryptedFile, "PGP MESSAGE", nil)
	if err != nil {
		fmt.Println("Erro ao criar o escritor de texto criptografado:", err)
		return
	}
	defer encryptedWriter.Close()

	// Obter o anel de chaves do destinatário
	readArmored, err := openpgp.ReadArmoredKeyRing(publicKeyASC)
	if err != nil {
		fmt.Println("Erro ao ler o anel de chaves do destinatário:", err)
		return
	}

	// Criar a entidade de escrita de texto criptografado
	plaintext, err := openpgp.Encrypt(encryptedWriter, readArmored, nil, nil, nil)
	if err != nil {
		fmt.Println("Erro ao criar a entidade de escrita de texto criptografado:", err)
		return
	}

	// Escrever o conteúdo do arquivo original no arquivo criptografado
	_, err = io.Copy(plaintext, &fileContent)
	if err != nil {
		fmt.Println("Erro ao escrever o conteúdo criptografado:", err)
		return
	}

	// Fechar a entidade de escrita de texto criptografado
	err = plaintext.Close()
	if err != nil {
		fmt.Println("Erro ao fechar a entidade de escrita de texto criptografado:", err)
		return
	}

	fmt.Println("Arquivo criptografado com sucesso!")
}

// func EncryptFile(publicKeyring, secretKeyring string, bits int, inputFile string, outputFile string) {
// 	pubKey := DecodePublicKey(publicKeyring)
// 	privKey := DecodePrivateKey(secretKeyring)

// 	to := CreateEntityFromKeys(pubKey, privKey, bits)

// 	input, err := os.Open(inputFile)
// 	if err != nil {
// 		log.Fatalf("Error opening input file: %s", err)
// 	}
// 	defer input.Close()

// 	output, err := os.Create(outputFile)
// 	if err != nil {
// 		log.Fatalf("Error creating output file: %s", err)
// 	}
// 	defer output.Close()

// 	w, err := armor.Encode(output, "Message", make(map[string]string))
// 	if err != nil {
// 		log.Fatalf("Error creating OpenPGP Armor: %s", err)
// 	}
// 	defer w.Close()

// 	plain, err := openpgp.Encrypt(w, []*openpgp.Entity{to}, nil, nil, nil)
// 	if err != nil {
// 		log.Fatalf("Error creating entity for encryption: %s", err)
// 	}
// 	defer plain.Close()

// 	compressed, err := gzip.NewWriterLevel(plain, gzip.BestCompression)
// 	if err != nil {
// 		log.Fatalf("Invalid compression level: %s", err)
// 	}

// 	n, err := io.Copy(compressed, input)
// 	if err != nil {
// 		fmt.Printf("Encrypted %d bytes\n", n)
// 		log.Fatalf("Error writing encrypted file: %s", err)
// 	}

// 	compressed.Close()
// }

func EncMessage() (*bytes.Buffer, error) {
	message := []byte("Agora deu bom")
	encryptedMessage := new(bytes.Buffer)

	publicKeyASC, err := os.Open("D:/OneDrive - Riversoft Integração e Desenvolvimento de Software Ltda/Documentos/Desenv/riversoft/stcpgpg/keys/Vinicius Matheus Santos_0x28352859_public.asc")
	if err != nil {
		fmt.Println(err)
		return nil, nil
	}
	defer publicKeyASC.Close()

	readArmoredKey, err := openpgp.ReadArmoredKeyRing(publicKeyASC)
	if err != nil {
		fmt.Println("Erro ao ler a chave pública do destinatário:", err)
		return nil, nil
	}

	plaintext, err := openpgp.Encrypt(encryptedMessage, readArmoredKey, nil, nil, nil)
	if err != nil {
		fmt.Println("Erro ao criptografar a mensagem:", err)
		return nil, nil
	}
	plaintext.Write(message)
	plaintext.Close()

	fmt.Println("Mensagem cript:", encryptedMessage.String())
	return encryptedMessage, nil
}

func EncTest(secretString, publicKeyring string) (string, error) {
	log.Println("Secret to hide:", secretString)
	log.Println("Public Keyring:", publicKeyring)

	// Read in public key
	keyringFileBuffer, _ := os.Open(publicKeyring)
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadArmoredKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}

	// encrypt string
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entityList, nil, nil, nil)
	if err != nil {
		return "", err
	}
	_, err = w.Write([]byte(secretString))
	if err != nil {
		return "", err
	}
	err = w.Close()
	if err != nil {
		return "", err
	}

	// Encode to base64
	bytes, err := io.ReadAll(buf)
	if err != nil {
		return "", err
	}
	encStr := base64.StdEncoding.EncodeToString(bytes)

	// Output encrypted/encoded string
	log.Println("Encrypted Secret:", encStr)

	return encStr, nil
}
