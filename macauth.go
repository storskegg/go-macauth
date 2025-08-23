package macauth

import (
    "crypto"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "hash"
    "os"
    "time"
)

const (
    PortHTTP  = "80"
    PortHTTPS = "443"
)

const (
    // EncodingDictionary contains all valid characters usable in the key, secret, and algorithm strings.
    EncodingDictionary = " !#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"
)

var Ports = map[string]string{
    "http":  PortHTTP,
    "https": PortHTTPS,
}

type Card struct {
    Timestamp        string `json:"timestamp"`
    Nonce            string `json:"nonce"`
    Method           string `json:"method"`
    Path             string `json:"path"`
    Host             string `json:"host"`
    Port             string `json:"port"`
    EnvVarNameKey    string `json:"envVarNameKey"`
    EnvVarNameSecret string `json:"envVarNameSecret"`
}

func (c *Card) Marshal() string {
    return ""
}

// Sign accepts a hash function, and a Card struct pointer, and returns a valid MAC header string. If the hash function
// is nil, it defaults to SHA3_256 as a logical default..
func Sign(hasher func() hash.Hash, card *Card) (string, error) {
    if hasher == nil {
        hasher = crypto.SHA3_256.New
    }
}

////////////////////////////////////////

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

func GetPortFromScheme(scheme string) (string, bool) {
    port, ok := Ports[scheme]
    return port, ok
}

// Key returns the value of the given env var name. Key corresponds to the MAC key identifier in the draft.
// https://tools.ietf.org/id/draft-ietf-oauth-v2-http-mac-02.html
func Key(envVar string) string {
    return os.Getenv(envVar)
}

// Secret returns the value of the given env var name. Secret corresponds to the MAC key in the draft.
// https://tools.ietf.org/id/draft-ietf-oauth-v2-http-mac-02.html
func Secret(envVar string) string {
    return os.Getenv(envVar)
}
