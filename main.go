package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/log"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	mode   string
	algo   string
	format string
	input  string
	path   string
	pass   string
)

const (
	AES_KeySize    = 32
	ChaCha_KeySize = 32
	Salt_Size      = 16
)

type CryptoolBlock struct {
	Salt  []byte
	Nonce []byte
	Data  []byte
}

func genKey(pass string, salt []byte, length uint32) []byte {
	return argon2.IDKey([]byte(pass), salt, 1, 64*1024, 4, length)
}

func run() {
	if mode == "encrypt" {
		c, salt := func() (cipher.AEAD, []byte) {
			s := make([]byte, Salt_Size)
			if _, err := rand.Read(s); err != nil {
				log.Error(err)
			}

			switch algo {
			case "aes":
				key := genKey(pass, s, AES_KeySize)

				c, err := aes.NewCipher(key)
				if err != nil {
					log.Error(err)
					os.Exit(1)
				}

				gcm, err := cipher.NewGCM(c)
				if err != nil {
					log.Error(err)
					os.Exit(1)
				}

				return gcm, s

			case "chacha":
				key := genKey(pass, s, ChaCha_KeySize)

				c, err := chacha20poly1305.New(key)
				if err != nil {
					log.Error(err)
					os.Exit(1)
				}

				return c, s
			}
			return nil, nil
		}()

		nonce := make([]byte, c.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			log.Error(err)
			os.Exit(1)
		}

		if format == "input" {
			enc := c.Seal(nil, nonce, []byte(input), nil)
			out := fmt.Sprintf("%s.%s.%s", base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(enc))
			log.Info("Done", "output", out)
		} else {
			data := func() []byte {
				b, err := os.ReadFile(path)
				if err != nil {
					log.Error(err)
					os.Exit(1)
				}
				return b
			}()
			enc := c.Seal(nil, nonce, data, nil)
			obj := CryptoolBlock{salt, nonce, enc}
			f, err := os.Create(fmt.Sprintf("%s.enc", path))
			if err != nil {
				log.Error(err)
				os.Exit(1)
			}
			defer f.Close()
			e := gob.NewEncoder(f)
			err = e.Encode(obj)
			if err != nil {
				log.Error(err)
				os.Exit(1)
			}
			log.Info("Done", "output", fmt.Sprintf("%s.enc", path))
		}
	} else {
		salt, nonce, ciphertext := func() ([]byte, []byte, []byte) {
			if format == "input" {
				strs := strings.Split(input, ".")
				s, e1 := base64.StdEncoding.DecodeString(strs[0])
				n, e2 := base64.StdEncoding.DecodeString(strs[1])
				ct, e3 := base64.StdEncoding.DecodeString(strs[2])
				if e1 != nil || e2 != nil || e3 != nil {
					log.Error(errors.New("invalid input string"))
					os.Exit(1)
				}
				return s, n, ct
			} else {
				obj := func() CryptoolBlock {
					f, err := os.Open(path)
					if err != nil {
						log.Error(err)
						os.Exit(1)
					}
					defer f.Close()
					var o CryptoolBlock
					gob.NewDecoder(f).Decode(&o)
					return o
				}()
				return obj.Salt, obj.Nonce, obj.Data
			}
		}()
		c := func() cipher.AEAD {
			switch algo {
			case "aes":
				key := genKey(pass, salt, AES_KeySize)

				c, err := aes.NewCipher(key)
				if err != nil {
					log.Error(err)
					os.Exit(1)
				}

				gcm, err := cipher.NewGCM(c)
				if err != nil {
					log.Error(err)
					os.Exit(1)
				}

				return gcm

			case "chacha":
				key := genKey(pass, salt, ChaCha_KeySize)

				c, err := chacha20poly1305.New(key)
				if err != nil {
					log.Error(err)
					os.Exit(1)
				}

				return c
			}
			return nil
		}()

		dec, err := c.Open(nil, nonce, ciphertext, nil)

		if err != nil {
			log.Error(err, "line", 132)
			os.Exit(1)
		}
		if format == "input" {
			log.Info("Done", "output", string(dec))
		} else {
			f, err := os.Create(fmt.Sprintf("%s.dec", strings.TrimSuffix(path, ".enc")))
			if err != nil {
				log.Error(err)
				os.Exit(1)
			}
			defer f.Close()
			f.Write(dec)
			log.Info("Done", "output", fmt.Sprintf("%s.dec", strings.TrimSuffix(path, ".enc")))
		}
	}
}

func main() {
	form := huh.NewForm(

		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select a mode").
				Options(
					huh.NewOption("Encrypt", "encrypt"),
					huh.NewOption("Decrypt", "decrypt"),
				).
				Value(&mode),

			huh.NewSelect[string]().
				Title("Select an algorithm").
				Options(
					huh.NewOption("AES-256-GCM", "aes"),
					huh.NewOption("XChaCha-Poly1305", "chacha"),
				).
				Value(&algo),

			huh.NewSelect[string]().
				Title("Select an input format").
				Description("If you choose file, the output will be to the path you choose with \".enc\" or \".dec\" appended depending on mode.").
				Options(
					huh.NewOption("Input", "input"),
					huh.NewOption("File", "file"),
				).
				Value(&format),
		),

		huh.NewGroup(
			huh.NewInput().
				Title("Provide a file path relative to the current working directory").
				Value(&path).
				Validate(func(str string) error {
					if _, err := os.Stat(str); os.IsNotExist(err) {
						return errors.New("that path does not exist")
					} else if os.IsPermission(err) {
						return errors.New("you don't have permission to access that path")
					}
					if _, err := os.Stat(fmt.Sprintf("%s.enc", str)); err == nil {
						return fmt.Errorf("the output location (%s.enc) already exists", str)
					} else if os.IsPermission(err) {
						return fmt.Errorf("you do not have permission to access the output location (%s.enc)", str)
					}
					return nil
				}),
		).WithHideFunc(func() bool {
			return format == "input" || mode == "decrypt"
		}),

		huh.NewGroup(
			huh.NewInput().
				Title("Provide a file path relative to the current working directory").
				Value(&path).
				Validate(func(str string) error {
					if _, err := os.Stat(str); os.IsNotExist(err) {
						return errors.New("that path does not exist")
					} else if os.IsPermission(err) {
						return errors.New("you don't have permission to access that path")
					}
					str2 := strings.TrimSuffix(str, ".enc")
					if _, err := os.Stat(fmt.Sprintf("%s.dec", str2)); err == nil {
						return fmt.Errorf("the output location (%s.dec) already exists", str2)
					} else if os.IsPermission(err) {
						return fmt.Errorf("you do not have permission to access the output location (%s.dec)", str2)
					}
					return nil
				}),
		).WithHideFunc(func() bool {
			return format == "input" || mode == "encrypt"
		}),

		huh.NewGroup(
			huh.NewText().
				Title("Provide an input string").CharLimit(400).
				Value(&input),
		).WithHideFunc(func() bool {
			return format == "file"
		}),

		huh.NewGroup(
			huh.NewInput().
				Title("Provide a password").
				Value(&pass),
		),
	).WithAccessible(os.Getenv("ACCESSIBLE") != "").WithTheme(huh.ThemeCatppuccin())

	if e := form.Run(); e != nil {
		log.Error(e)
		os.Exit(1)
	}

	run()
}

func init() {
	gob.Register(CryptoolBlock{})
}
