package gpgutils

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	opengpg "github.com/ProtonMail/gopenpgp/v2/crypto"
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

	key, err := opengpg.NewKeyFromEntity(entity)
	if err != nil {
		return errors.New("gopenpgp: unable to generate new key")
	}
	defer key.ClearPrivateParams()

	locked, err := key.Lock([]byte(passphrase))
	if err != nil {
		return errors.New("gopenpgp: unable to lock new key")
	}
	locked.Armor()

	for _, id := range key.GetEntity().Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, key.GetEntity().PrimaryKey, key.GetEntity().PrivateKey, config)
		if err != nil {
			return err
		}
	}

	// for _, id := range entity.Identities {
	// 	err := id.SelfSignature.SignUserId(id.UserId.Id, entity.PrimaryKey, entity.PrivateKey, config)
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	// if passphrase != "" {
	// 	if entity.PrivateKey != nil {
	// 		err = entity.PrivateKey.Encrypt([]byte(passphrase))
	// 		if err != nil {
	// 			return err
	// 		}
	// 	} else {
	// 		return errors.New("chave privada não está disponível")
	// 	}
	// }

	if passphrase != "" {
		if key.GetEntity().PrivateKey != nil {
			err = key.GetEntity().EncryptPrivateKeys([]byte(passphrase), config)
			if err != nil {
				return err
			}
		} else {
			return errors.New("chave privada não está disponível")
		}
	}

	// Escrita da chave pública em um arquivo
	publicKeyFile, err := os.Create(fmt.Sprintf("%s_public.asc", filePath))
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	publicKeyWriter, err := armor.Encode(publicKeyFile, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	defer publicKeyWriter.Close()

	// err = entity.Serialize(publicKeyWriter)
	// if err != nil {
	// 	return err
	// }
	err = key.GetEntity().Serialize(publicKeyWriter)
	if err != nil {
		return err
	}

	// Escrita da chave privada em um arquivo
	privateKeyFile, err := os.Create(fmt.Sprintf("%s_SECRET.asc", filePath))
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	privateKeyWriter, err := armor.Encode(privateKeyFile, openpgp.PrivateKeyType, nil)
	if err != nil {
		return err
	}
	defer privateKeyWriter.Close()

	// err = entity.SerializePrivate(privateKeyWriter, config)
	// if err != nil {
	// 	return err
	// }

	err = key.GetEntity().SerializePrivate(privateKeyWriter, config)
	if err != nil {
		return err
	}

	fmt.Printf("uid: \"%s (%s) <%s>\"\n", name, comment, email)
	if expirationDate != nil {
		fmt.Printf("Chaves pública e privada criadas e assinadas. %s_public.asc e %s_SECRET.asc [expires: %s]\n", filePath, filePath, expirationDate.Format("02/01/2006 15:04:05"))
	} else {
		fmt.Printf("Chaves pública e privada criadas e assinadas. %s_public.asc e %s_SECRET.asc\n", filePath, filePath)
	}

	return nil
}
