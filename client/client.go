package client

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"hash"
	"net/url"
	"strings"

	macauth "keybase/hmac-header"
)

var (
	ErrMalformedURLString   = errors.New("url string must be a fully qualified url")
	ErrUnsupportedURLScheme = errors.New("unsupported URL scheme. please use http or https")
)

func Sign(hashAlg func() hash.Hash, card *macauth.Card) (string, error) {
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

	if hashAlg == nil {
		hashAlg = crypto.SHA3_256.New
	}

	secret := macauth.Secret(card.EnvVarNameSecret)

	h := hmac.New(hashAlg, []byte(secret))
	_, err := h.Write(signature)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

type MacHeaderOptions struct {
	Method           string `json:"method"`
	Timestamp        string `json:"timestamp"`
	Nonce            string `json:"nonce"`
	EnvVarNameKey    string `json:"envVarNameKey"`
	EnvVarNameSecret string `json:"envVarNameSecret"`
	HashAlg          func() hash.Hash
}

func MacHeaderString(urlString string, options *MacHeaderOptions) (string, error) {
	if urlString == "" {
		return "", ErrMalformedURLString
	}

	var err error
	var id, timestamp, nonce, mac string
	var method, host, path, port string

	if u, err := url.Parse(urlString); err != nil {
		return "", err
	} else {
		host = u.Host
		path = u.RequestURI()
		port = u.Port()
		if u.Scheme == "" {
			return "", ErrMalformedURLString
		}
		if port == "" {
			var ok bool
			port, ok = macauth.GetPortFromScheme(strings.ToLower(u.Scheme))
			if !ok {
				return "", ErrUnsupportedURLScheme
			}
		}
	}
	if host == "" || path == "" {
		return "", ErrMalformedURLString
	}

	if options.Nonce == "" {
		nonce, err = macauth.RandHex()
		if err != nil {
			return "", err
		}
	} else {
		nonce = options.Nonce
	}

	if options.Method == "" {
		method = "GET"
	} else {
		method = strings.ToUpper(options.Method)
	}

	if options.Timestamp == "" {
		options.Timestamp = macauth.Now()
	} else {
		timestamp = options.Timestamp
	}

	id = macauth.Key(options.EnvVarNameKey)

	mac, err = Sign(options.HashAlg, &macauth.Card{
		Timestamp:        timestamp,
		Nonce:            nonce,
		Method:           method,
		Path:             path,
		Host:             host,
		Port:             port,
		EnvVarNameKey:    options.EnvVarNameKey,
		EnvVarNameSecret: options.EnvVarNameSecret,
	})
	if err != nil {
		return "", err
	}

	return `MAC id="` + id + `", ts="` + timestamp + `", nonce="` + nonce + `", mac="` + mac + `"`, nil
}
