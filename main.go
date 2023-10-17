package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"time"

	"gocryptopgp/pkg/gpgutils"
)

const (
	// 	prefix      = "keys"
	pubkey  = "keys/testando-com-pass_public.asc"
	privkey = "keys/testando-com-pass_SECRET.asc"

// name       = "teste da silva"
// comment    = "comentario do teste"
// email      = "teste@teste"
// keySize    = 2048
// passphrase = "teste"
)

func main() {
	// err := gpgutils.EncryptMessageArmored(pubkey, "file-tests/teste.txt")
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// err = gpgutils.DecryptMessageArmored(privkey, "file-tests/teste.txt.gpg", "teste123")
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// hashutils.OpenAndCompareHashFiles("file-tests/teste.txt.gpg", "file-tests/teste.txt")
	// os.Exit(1)
	// gpgutils.KeyPairWriter(prefix, name, comment, email, passphrase, nil, keySize)
	// gpgutils.EncryptSignMessageArmored(pubkey, privkey, passphrase, filePath)
	// err := gpgutils.DecryptVerifyMessageArmored(pubkey, privkey, passphrase, encFilePath)

	var (
		filePath        string
		name            string
		comment         string
		email           string
		keySize         int
		passphrase      string
		newPassphrase   string
		expirationInput string
		expirationTime  time.Time
	)

	var privateKey, publicKey, keyOut, fileIn, fileOut string
	// flags da aplicação
	flag.StringVar(&privateKey, "privateKey", "", "[Directory name of private key]")
	flag.StringVar(&publicKey, "publicKey", "", "[Directory name to public key]")

	flag.Parse()

	if flag.NArg() == 0 || (flag.Arg(0) != "encrypt" && flag.Arg(0) != "decrypt" && flag.Arg(0) != "keygen") {
		errorMessage := "Error: Subcommand " + flag.Arg(0) + " is not available"
		fmt.Println(errorMessage)
		usage()
		return
	}

	switch {
	case flag.Arg(0) == "encrypt":

		if publicKey == "" {
			fmt.Println("Error: -publicKey is required")
			usage()
			return
		}

		fs := flag.NewFlagSet("encrypt [flags]", flag.ExitOnError)

		fs.StringVar(&fileIn, "fileIn", "", "[Input file to encrypt]")
		fs.StringVar(&fileOut, "fileOut", "", "[Output encrypted file]")
		sygn := fs.Bool("sign", false, "[Declare passphrase to sygn encrypted file]")

		fs.Parse(flag.Args()[1:])

		if *sygn {

			if privateKey == "" {
				fmt.Println("Error: -privateKey is required")
				usage()
				return
			}

			for passphrase == "" {
				fmt.Print("Passphrase para assinatura: ")
				fmt.Scanln(&passphrase)
			}

			err := gpgutils.EncryptSignMessageArmored(publicKey, privateKey, passphrase, fileIn, fileOut)
			if err != nil {
				log.Fatal(err.Error())
			}

		} else {
			err := gpgutils.EncryptMessageArmored(publicKey, fileIn, fileOut)
			if err != nil {
				log.Fatal(err.Error())
			}
		}

	case flag.Arg(0) == "decrypt":

		if privateKey == "" {
			fmt.Println("Error: -privateKey is required")
			usage()
			return
		}

		fs := flag.NewFlagSet("decrypt [flags]", flag.ExitOnError)

		fs.StringVar(&fileIn, "fileIn", "", "[Input file to decrypt]")
		fs.StringVar(&fileOut, "fileOut", "", "[Output decrypted file]")
		verify := fs.Bool("verify", false, "[Declare passphrase to verify encrypted file]")

		fs.Parse(flag.Args()[1:])

		if *verify {

			if publicKey == "" {
				fmt.Println("Error: -publicKey is required")
				usage()
				return
			}

			for passphrase == "" {
				fmt.Print("Passphrase: ")
				fmt.Scanln(&passphrase)
			}
			err := gpgutils.DecryptVerifyMessageArmored(publicKey, privateKey, passphrase, fileIn, fileOut)
			if err != nil {
				log.Fatal(err.Error())
			}

		} else {
			fmt.Print("Passphrase (''): ")
			fmt.Scanln(&passphrase)
			err := gpgutils.DecryptMessageArmored(privateKey, fileIn, passphrase, fileOut)
			if err != nil {
				log.Fatal(err.Error())
			}
		}

	case flag.Arg(0) == "keygen":

		fs := flag.NewFlagSet("keygen [Generates a new public/private key pair]", flag.ExitOnError)

		fs.StringVar(&keyOut, "d", "./keys", "[Output directory of key files]")
		pass := fs.Bool("passphrase", false, "[Define passphrase]")
		expTime := fs.Bool("expiration", false, "[Define key expiration time]")
		newPass := fs.Bool("newPassphrase", false, "[Define passphrase]")
		verify := fs.Bool("verify", false, "[Define passphrase]")

		fs.Parse(flag.Args()[1:])

		if *verify {
			err := gpgutils.VerifyKeyPair(publicKey, privateKey)
			if err != nil {
				log.Fatal(err)
			}
			os.Exit(1)
		}

		if *newPass {
			if privateKey == "" {
				fmt.Println("Error: -privateKey is required")
				usage()
				return
			}

			fmt.Print("Old Passphrase: ")
			fmt.Scanln(&passphrase)
			fmt.Print("New Passphrase: ")
			fmt.Scanln(&newPassphrase)
			err := gpgutils.UpdatePrivateKeyPassphrase(privateKey, passphrase, newPassphrase)
			if err != nil {
				log.Fatal(err)
			}
			os.Exit(1)
		}

		fmt.Println("gpg (Test GPG) 1.0.0; Copyright (C) 2023")
		fmt.Println("Test GPG needs to construct a user ID to identify your key.")
		fmt.Println("")

		// Solicitar o caminho do arquivo para salvar a chave
		fmt.Print("Diretório e Prefixo das chaves ('./default-key'): ")
		fmt.Scanln(&filePath)
		if filePath == "" {
			filePath = "./default-key"
		}

		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Nome Completo: ")
		name, _ = reader.ReadString('\n')

		fmt.Print("Comentário: ")
		comment, _ = reader.ReadString('\n')

		for {
			fmt.Print("Endereço de Email: ")
			fmt.Scanln(&email)
			if ok := validMailAddress(email); !ok {
				fmt.Println("Email válido, digite novamente")
				continue
			} else {
				break
			}
		}
		fmt.Printf("Você selecionou este identificador de utilizador:\n \"%s (%s) <%s>\"\n", strings.TrimSpace(name), strings.TrimSpace(comment), strings.TrimSpace(email))

	loop:
		for {
			fmt.Print("Mudar (N)ome, (C)omentário, (E)mail ou (O)k/(S)air? ")
			option, _ := reader.ReadString('\n')
			option = strings.TrimSpace(strings.ToLower(option))

			switch option {
			case "n":
				fmt.Print("Nome Completo: ")
				name, _ = reader.ReadString('\n')
			case "c":
				fmt.Print("Comentário: ")
				comment, _ = reader.ReadString('\n')
			case "e":
				for {
					fmt.Print("Endereço de Email: ")
					fmt.Scanln(&email)
					if ok := validMailAddress(email); !ok {
						fmt.Println("Email válido, digite novamente")
						continue
					} else {
						break
					}
				}
			case "o":
				break loop
			case "s":
				log.Fatal("gpg: Geração de chave cancelada. ")
			default:
				fmt.Println("Opção inválida. Tente novamente.")
			}
			fmt.Printf("Você selecionou este identificador de utilizador:\n \"%s (%s) <%s>\"\n", strings.TrimSpace(name), strings.TrimSpace(comment), strings.TrimSpace(email))
		}

		name = strings.TrimSpace(name)
		comment = strings.TrimSpace(comment)
		email = strings.TrimSpace(email)

		for keySize != 1024 && keySize != 2048 && keySize != 4096 {
			fmt.Println("Numero de bits para tamanho das chaves:\n[1024 bits] [2048 bits] [4096 bits]")
			fmt.Print("Digite o tamanho (2048): ")
			fmt.Scanln(&keySize)
			if keySize == 0 {
				keySize = 2048
			}
		}

		if *pass {
			fmt.Print("Passphrase (''): ")
			fmt.Scanln(&passphrase)
		}

		for {
			if *expTime {
				fmt.Println(`
Por favor especifique por quanto tempo a chave deve ser válida.
   0 = chave não expira
<n>d = chave expira em n dias
<n>w = chave expira em n semanas
<n>m = chave expira em n meses
<n>y = chave expira em n anos`)
				fmt.Print("A chave é valida por? (0) ")
				fmt.Scanln(&expirationInput)
				if expirationInput != "" {
					dataExp, err := parseDuracaoChave(expirationInput)
					if err != nil {
						fmt.Println("Entrada inválida:", err)
						continue
					}
					fmt.Printf("A Chave expira em %s Hora oficial do Brasil\n", dataExp.Format("02/01/2006 15:04:05"))
					expirationTime = dataExp
					break
				} else {
					expirationInput = "0"
					fmt.Println("A Chave não expira.")
					break
				}
			}
		}

		err := gpgutils.KeyPairWriter(filePath, name, comment, email, passphrase, &expirationTime, keySize)
		if err != nil {
			log.Fatal(err)
		}

	default:
		usage()
		return
	}
}

// Analisar a entrada de duração da chave e retornar os valores de duração e unidade
func parseDuracaoChave(duracaoChave string) (time.Time, error) {
	if duracaoChave == "" {
		return time.Now(), nil
	}
	unidade := string(duracaoChave[len(duracaoChave)-1])
	duracaoStr := duracaoChave[:len(duracaoChave)-1]

	duracao, err := strconv.Atoi(duracaoStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("ocorreu um erro ao obter a duração")
	}

	switch unidade {
	case "d":
		return time.Now().AddDate(0, 0, duracao), nil
	case "w":
		return time.Now().AddDate(0, 0, duracao*7), nil
	case "m":
		return time.Now().AddDate(0, duracao, 0), nil
	case "y":
		return time.Now().AddDate(duracao, 0, 0), nil
	default:
		return time.Now(), fmt.Errorf("ocorreu um erro ao obter a unidade")
	}
}

func validMailAddress(address string) bool {
	if address == "" {
		return true
	}
	_, err := mail.ParseAddress(address)
	if err != nil {
		return false
	}
	return true
}

func usage() {
	fmt.Println()
	fmt.Println("Available flags before subcommands encrypt or decrypt:")
	fmt.Println("  -privateKey string: specify privateKey")
	fmt.Println("  -publicKey string: specify publicKey")
	fmt.Println()
	fmt.Println("Available flags after subcommand encrypt:")
	fmt.Println("  -file string: specify file to encrypting process")
	fmt.Println()
	fmt.Println("Available flags after subcommand encrypt:")
	fmt.Println("  -file string: specify file to decrypting process")
	fmt.Println()
	fmt.Println("Available flags after subcommand keygen:")
	fmt.Println("  -passphrase string: Define if passphrase is on")
	fmt.Println("  -expiration string: Define if keys expiration time is on")
	fmt.Println()
}

// fmt.Println(`Supported algorithms:
// Pubkey: RSA, ELG, DSA, ECDH, ECDSA, EDDSA
// Cipher: IDEA, 3DES, CAST5, BLOWFISH, AES, AES192, AES256, TWOFISH,
// 				CAMELLIA128, CAMELLIA192, CAMELLIA256
// Hash: SHA1, RIPEMD160, SHA256, SHA384, SHA512, SHA224
// Compression: Uncompressed, ZIP, ZLIB, BZIP2

// Syntax: gpg [options] [files]
// Sign, check, encrypt or decrypt
// Default operation depends on the input data

// Commands:

//  -s, --sign                         make a signature
// 		 --clear-sign                   make a clear text signature
//  -b, --detach-sign                  make a detached signature
//  -e, --encrypt                      encrypt data
//  -c, --symmetric                    encryption only with symmetric cipher
//  -d, --decrypt                      decrypt data (default)
// 		 --verify                       verify a signature
//  -k, --list-keys                    list keys
// 		 --list-signatures              list keys and signatures
// 		 --check-signatures             list and check key signatures
// 		 --fingerprint                  list keys and fingerprints
//  -K, --list-secret-keys             list secret keys
// 		 --generate-key                 generate a new key pair
// 		 --quick-generate-key           quickly generate a new key pair
// 		 --quick-add-uid                quickly add a new user-id
// 		 --quick-revoke-uid             quickly revoke a user-id
// 		 --quick-set-expire             quickly set a new expiration date
// 		 --full-generate-key            full featured key pair generation
// 		 --generate-revocation          generate a revocation certificate
// 		 --delete-keys                  remove keys from the public keyring
// 		 --delete-secret-keys           remove keys from the secret keyring
// 		 --quick-sign-key               quickly sign a key
// 		 --quick-lsign-key              quickly sign a key locally
// 		 --quick-revoke-sig             quickly revoke a key signature
// 		 --sign-key                     sign a key
// 		 --lsign-key                    sign a key locally
// 		 --edit-key                     sign or edit a key
// 		 --change-passphrase            change a passphrase
// 		 --export                       export keys
// 		 --send-keys                    export keys to a keyserver
// 		 --receive-keys                 import keys from a keyserver
// 		 --search-keys                  search for keys on a keyserver
// 		 --refresh-keys                 update all keys from a keyserver
// 		 --import                       import/merge keys
// 		 --card-status                  print the card status
// 		 --edit-card                    change data on a card
// 		 --change-pin                   change a card's PIN
// 		 --update-trustdb               update the trust database
// 		 --print-md                     print message digests
// 		 --server                       run in server mode
// 		 --tofu-policy VALUE            set the TOFU policy for a key

// Options controlling the configuration:
// 		 --default-key NAME             use NAME as default secret key
// 		 --encrypt-to NAME              encrypt to user ID NAME as well
// 		 --group SPEC                   set up email aliases
// 		 --openpgp                      use strict OpenPGP behavior
//  -n, --dry-run                      do not make any changes
//  -i, --interactive                  prompt before overwriting

// Options controlling the output:
//  -o, --output FILE                  write output to FILE
//  -z N                               set compress level to N (0 disables)

// Options controlling key import and export:
// 		 --auto-key-locate MECHANISMS   use MECHANISMS to locate keys by mail address
// 		 --auto-key-import              import missing key from a signature
// 		 --include-key-block            include the public key in signatures
// 		 --disable-dirmngr              disable all access to the dirmngr

// Options to specify keys:
//  -r, --recipient USER-ID            encrypt for USER-ID
//  -u, --local-user USER-ID           use USER-ID to sign or decrypt

// (See the man page for a complete listing of all commands and options)

// Examples:

//  -se -r Bob [file]          sign and encrypt for user Bob
//  --clear-sign [file]        make a clear text signature
//  --detach-sign [file]       make a detached signature
//  --list-keys [names]        show keys
//  --fingerprint [names]      show fingerprints`)
