package gpgutils

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	openpgp "github.com/ProtonMail/go-crypto/openpgp"
	packet "github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

func KeyPairWriter(filePath, name, comment, email, passphrase string, expirationDate *time.Time, keySize int) error {
	var expirationSeconds uint32

	if email == "" && name == "" {
		return errors.New("STCPgpg: Nome e email não foram configurados")
	}

	if expirationDate != nil {
		// Calcular a duração em segundos até a data de expiração
		duration := time.Until(*expirationDate)
		expirationSeconds = uint32(duration.Seconds())
	}

	config := &packet.Config{
		Algorithm:              packet.PubKeyAlgoRSA,
		RSABits:                keySize,
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		KeyLifetimeSecs:        expirationSeconds,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
	}

	// Criação da chave pública
	entity, err := openpgp.NewEntity(name, comment, email, config)
	if err != nil {
		return errors.New("gopengpp: error in encoding new entity")
	}

	if entity.PrivateKey == nil {
		return errors.New("gopenpgp: error in generating private key")
	}

	key, err := openpgpcrypto.NewKeyFromEntity(entity)
	if err != nil {
		return errors.New("gopenpgp: unable to generate new key")
	}
	defer key.ClearPrivateParams()

	locked, err := key.Lock([]byte(passphrase))
	if err != nil {
		return errors.New("gopenpgp: unable to lock new key")
	}

	armoredpriv, err := locked.Armor()
	if err != nil {
		return err
	}

	armoredpub, err := key.GetArmoredPublicKey()
	if err != nil {
		return err
	}

	// Escrita da chave pública em um arquivo
	publicKeyFile, err := os.Create(fmt.Sprintf("%s_public.asc", filePath))
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	_, err = publicKeyFile.Write([]byte(armoredpub))
	if err != nil {
		return err
	}

	// Escrita da chave privada em um arquivo
	privateKeyFile, err := os.Create(fmt.Sprintf("%s_SECRET.asc", filePath))
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()
	_, err = privateKeyFile.Write([]byte(armoredpriv))
	if err != nil {
		return err
	}

	fmt.Printf("uid: \"%s (%s) <%s>\"\n", strings.TrimSpace(name), strings.TrimSpace(comment), strings.TrimSpace(email))
	if expirationDate != nil {
		fmt.Printf("Chaves pública e privada criadas e assinadas. %s_public.asc e %s_SECRET.asc [expires: %s]\n", filePath, filePath, expirationDate.Format("02/01/2006 15:04:05"))
	} else {
		fmt.Printf("Chaves pública e privada criadas e assinadas. %s_public.asc e %s_SECRET.asc\n", filePath, filePath)
	}

	return nil
}

func UpdatePrivateKeyPassphrase(privateKey string, oldPassphrase string, newPassphrase string) error {
	if _, err := os.Stat(privateKey); os.IsNotExist(err) {
		return fmt.Errorf("chave privada não encontrada")
	}

	keyFile, err := os.OpenFile(privateKey, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("falha ao abrir o arquivo: %s", err)
	}
	defer keyFile.Close()

	keyBytesContent, err := io.ReadAll(keyFile)
	if err != nil {
		return fmt.Errorf("falha ao ler o arquivo: %s", err)
	}
	keyStringContent := string(keyBytesContent)

	armored, err := helper.UpdatePrivateKeyPassphrase(keyStringContent, []byte(oldPassphrase), []byte(newPassphrase))
	if err != nil {
		return fmt.Errorf("falha ao atualizar a frase de acesso da chave privada: %s", err)
	}

	_, err = keyFile.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("falha ao voltar para o início do arquivo: %s", err)
	}

	err = keyFile.Truncate(0)
	if err != nil {
		return fmt.Errorf("falha ao limpar o conteúdo do arquivo: %s", err)
	}

	// Escreve a chave privada atualizada no arquivo
	_, err = keyFile.WriteString(armored)
	if err != nil {
		return fmt.Errorf("falha ao escrever a chave privada no arquivo: %s", err)
	}

	fmt.Println("Passphrase atualizada com sucesso")

	return nil
}

func VerifyKeyPair(publicKeyPath, privateKeyPath string) error {
	// Abra o arquivo da chave pública
	publicKeyFile, err := os.Open(publicKeyPath)
	if err != nil {
		return fmt.Errorf("erro ao abrir o arquivo da chave pública: %v", err)
	}
	defer publicKeyFile.Close()

	// Abra o arquivo da chave privada
	privateKeyFile, err := os.Open(privateKeyPath)
	if err != nil {
		return fmt.Errorf("erro ao abrir o arquivo da chave privada: %v", err)
	}
	defer privateKeyFile.Close()

	// Leia a chave pública
	pubEntity, err := openpgp.ReadArmoredKeyRing(publicKeyFile)
	if err != nil {
		return fmt.Errorf("erro ao ler a chave pública: %v", err)
	}

	// Leia a chave privada
	privEntity, err := openpgp.ReadArmoredKeyRing(privateKeyFile)
	if err != nil {
		return fmt.Errorf("erro ao ler a chave privada: %v", err)
	}

	// Obtenha a chave pública
	pubKey := pubEntity[0].PrimaryKey
	if pubKey == nil {
		return err
	}

	// Obtenha a chave privada
	privKey := privEntity[0].PrivateKey
	if privKey == nil {
		return err
	}

	userId := pubEntity[0].PrimaryIdentity().UserId.Id

	idKeyString := pubKey.KeyIdString()
	creation := pubKey.CreationTime
	keyLifeTime := pubEntity[0].PrimaryIdentity().SelfSignature.KeyLifetimeSecs
	expiration := creation.Add(time.Second * time.Duration(*keyLifeTime))

	bits, err := pubKey.BitLength()
	if err != nil {
		return err
	}

	isValid := pubKey.CanSign() && privKey.Encrypted

	fmt.Printf("Certificados:\n")

	fmt.Printf(" - User ID: %v\n", userId)
	fmt.Printf(" - ID da Chave: %v\n", idKeyString)
	fmt.Printf(" - Válido até: %v | ", expiration.Format("02/01/2006"))
	current := time.Now()

	if current.After(expiration) {
		// A chave está expirada
		fmt.Println("A chave está expirada.")
	} else {
		// A chave ainda é válida
		fmt.Println("A chave ainda é válida.")
	}
	fmt.Printf(" - Bits: %v\n", bits)

	if isValid {
		fmt.Println(" - Tem assinatura")
	} else {
		fmt.Println(" - Não tem assinatura")
	}

	return nil
}
