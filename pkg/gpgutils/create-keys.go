package gpgutils

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	openpgp "github.com/ProtonMail/go-crypto/openpgp"
	packet "github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
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
