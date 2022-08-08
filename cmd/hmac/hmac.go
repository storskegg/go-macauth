package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"

	_ "golang.org/x/crypto/sha3"
)

type Card struct {
	Timestamp        string
	Nonce            string
	Method           string
	Path             string
	Host             string
	Port             string
	EnvVarNameKey    string
	EnvVarNameSecret string
}

func KeyString(envVar string) string {
	return os.Getenv(envVar)
}

func SecretBytes(envVar string) []byte {
	return []byte(os.Getenv(envVar))
}

func Now() string {
	return fmt.Sprintf("%d", time.Now().UTC().Unix())
}

func RandHex() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b)[0:32], nil
}

func Sign(card *Card) (string, error) {
	signature := []byte(strings.Join([]string{
		card.Timestamp,
		card.Nonce,
		card.Method,
		card.Path,
		card.Host,
		card.Port,
		"",
		"",
	}, "\n"))

	myhmac := sha3.NewCShake256(nil, []byte(os.Getenv("ENVIRONMENT")))
	_, err := myhmac.Write(SecretBytes(card.EnvVarNameSecret))
	if err != nil {
		return "", err
	}

	_, err = myhmac.Write(signature)
	if err != nil {
		return "", err
	}

	digest := make([]byte, 32)
	_, err = myhmac.Read(digest)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(digest), nil
}

func MacHeader(url *url.URL, method, timestamp, envKey, envSecret string) (string, error) {
	nonce, err := RandHex()
	if err != nil {
		return "", err
	}

	card := Card{
		Timestamp:        timestamp,
		Nonce:            nonce,
		Method:           method,
		Path:             url.RequestURI(),
		Host:             strings.ToLower(url.Host),
		Port:             url.Port(),
		EnvVarNameKey:    envKey,
		EnvVarNameSecret: envSecret,
	}

	mac, err := Sign(&card)
	if err != nil {
		return "", err
	}

	return strings.Join([]string{
		`MAC id="` + KeyString(card.EnvVarNameKey) + `"`,
		`ts="` + card.Timestamp + `"`,
		`nonce="` + card.Nonce + `"`,
		`mac="` + mac + `"`,
	}, ", "), nil
}

func main() {
	os.Setenv("MY_KEY", "secretKeyID")
	os.Setenv("MY_SECRET", "soSecret1")

	earl, err := url.Parse("https://sub.yourdomain.com/some/path?with=query&another=11112222")
	if err != nil {
		panic(err)
	}

	header, err := MacHeader(earl, "GET", Now(), "MY_KEY", "MY_SECRET")
	if err != nil {
		panic(err)
	}

	fmt.Println("Authorization: " + header)
}
