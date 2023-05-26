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

	"stcpgpg/pkg/gpgutils"
)

const (
	prefix      = "keys"
	pubkey      = "keys_public.asc"
	privkey     = "keys_SECRET.asc"
	filePath    = "file-tests/teste.txt"
	encFilePath = "file-tests/teste.txt.gpg"

	name       = "teste da silva"
	comment    = "comentario do teste"
	email      = "teste@teste"
	keySize    = 2048
	passphrase = "teste"
)

func main() {
	// gpgutils.KeyPairWriter(prefix, name, comment, email, passphrase, nil, keySize)
	// gpgutils.EncryptMessageArmored(pubkey, filePath)
	// gpgutils.DecryptMessageArmored(privkey, encFilePath, "teste")
	// gpgutils.EncryptSignMessageArmored(pubkey, privkey, passphrase, filePath)
	err := gpgutils.DecryptVerifyMessageArmored(pubkey, privkey, passphrase, encFilePath)
	if err != nil {
		fmt.Println(err)
	}

	os.Exit(1)

	var (
		filePath        string
		name            string
		comment         string
		email           string
		keySize         int
		passphrase      string
		expirationInput string
		expirationTime  time.Time
	)

	var secretKey, publicKey, keyOutputDir, fileToEncrypt, fileToDecrypt string
	// flags da aplicação
	flag.StringVar(&secretKey, "secretKey", "keys/Vinicius Matheus Santos_0x28352859_SECRET.asc", "[Directory path to configs app]")
	flag.StringVar(&publicKey, "publicKey", "", "[Directory path to backup]")

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

		fs.StringVar(&fileToEncrypt, "file", "", "[File path to encrypt]")
		sygn := fs.Bool("sygn", false, "[Declare passprhase to sygn encrypted file]")

		fs.Parse(flag.Args()[1:])

		if *sygn {
			for passphrase == "" {
				fmt.Print("Digite a passphrase para assinatura: ")
				fmt.Scanln(&passphrase)
			}
			err := gpgutils.EncryptSignMessageArmored(publicKey, secretKey, passphrase, fileToEncrypt)
			if err != nil {
				log.Fatal(err.Error())
			}
		} else {
			err := gpgutils.EncryptMessageArmored(publicKey, filePath)
			if err != nil {
				log.Fatal(err.Error())
			}
		}

	case flag.Arg(0) == "decrypt":

		if secretKey == "" {
			fmt.Println("Error: -secretKey is required")
			usage()
			return
		}

		fs := flag.NewFlagSet("decrypt [flags]", flag.ExitOnError)

		fs.StringVar(&fileToDecrypt, "file", "", "[File path to decrypt]")
		verify := fs.Bool("verify", false, "[Declare passprhase to verify encrypted file]")

		fs.Parse(flag.Args()[1:])

		if *verify {
			for passphrase == "" {
				fmt.Print("Digite a passphrase: ")
				fmt.Scanln(&passphrase)
			}
			err := gpgutils.DecryptVerifyMessageArmored(publicKey, secretKey, passphrase, fileToDecrypt)
			if err != nil {
				log.Fatal(err.Error())
			}
		} else {
			err := gpgutils.DecryptMessageArmored(secretKey, filePath, passphrase)
			if err != nil {
				log.Fatal(err.Error())
			}
		}

	case flag.Arg(0) == "keygen":

		fs := flag.NewFlagSet("keygen [Generates a new public/private key pair]", flag.ExitOnError)

		fs.StringVar(&keyOutputDir, "d", "./keys", "[Output directory of key files]")
		pass := fs.Bool("passphrase", false, "[Define if passphrase is on]")
		expTime := fs.Bool("expiration", false, "[Define if keys expiration time is on]")

		fs.Parse(flag.Args()[1:])

		fmt.Println("gpg (STCP GPG) 1.0.0; Copyright (C) 2023")
		fmt.Println("STCP GPG needs to construct a user ID to identify your key.")
		fmt.Println("")

		// Solicitar o caminho do arquivo para salvar a chave
		fmt.Print("Diretório e Prefixo das chaves ('./key-defaultname'): ")
		fmt.Scanln(&filePath)
		if filePath == "" {
			filePath = "./key-defaultname"
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
	fmt.Println("  -secretKey string: specify secretKey")
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
