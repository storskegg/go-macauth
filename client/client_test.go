package client

import (
	"crypto/sha1"
	"crypto/sha256"
	"hash"
	"os"
	"testing"

	macauth "keybase/hmac-header"

	"github.com/davecgh/go-spew/spew"
	"github.com/jzelinskie/whirlpool"
	"golang.org/x/crypto/sha3"
)

const (
	envKeyName    = "A_HMAC_KEY"
	envSecretName = "A_HMAC_SECRET"
)

func TestKey(t *testing.T) {
	type args struct {
		envVar string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := macauth.Key(tt.args.envVar); got != tt.want {
				t.Errorf("Key() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkMacHeaderString(b *testing.B) {
	type args struct {
		urlString string
		options   *MacHeaderOptions
	}

	tests := []struct {
		name string
		envs map[string]string
		args args
	}{
		{
			name: "SHA1",
			envs: map[string]string{
				envKeyName:    "h480djs93hd8",
				envSecretName: "489dks293j39",
			},
			args: args{
				urlString: "http://example.com/resource/1?b=1&a=2",
				options: &MacHeaderOptions{
					Method:           "Get",
					Timestamp:        "1336363200",
					Nonce:            "dj83hs9s",
					EnvVarNameKey:    envKeyName,
					EnvVarNameSecret: envSecretName,
					HashAlg:          sha1.New,
				},
			},
		}, {
			name: "SHA256",
			envs: map[string]string{
				envKeyName:    "h480djs93hd8",
				envSecretName: "489dks293j39",
			},
			args: args{
				urlString: "http://example.com/resource/1?b=1&a=2",
				options: &MacHeaderOptions{
					Method:           "Get",
					Timestamp:        "1336363200",
					Nonce:            "dj83hs9s",
					EnvVarNameKey:    envKeyName,
					EnvVarNameSecret: envSecretName,
					HashAlg:          sha256.New,
				},
			},
		},
		{
			name: "SHA3-256",
			envs: map[string]string{
				envKeyName:    "h480djs93hd8",
				envSecretName: "489dks293j39",
			},
			args: args{
				urlString: "http://example.com/resource/1?b=1&a=2",
				options: &MacHeaderOptions{
					Method:           "Get",
					Timestamp:        "1336363200",
					Nonce:            "dj83hs9s",
					EnvVarNameKey:    envKeyName,
					EnvVarNameSecret: envSecretName,
					HashAlg:          sha3.New256,
				},
			},
		},
		{
			name: "SHA3-384",
			envs: map[string]string{
				envKeyName:    "h480djs93hd8",
				envSecretName: "489dks293j39",
			},
			args: args{
				urlString: "http://example.com/resource/1?b=1&a=2",
				options: &MacHeaderOptions{
					Method:           "Get",
					Timestamp:        "1336363200",
					Nonce:            "dj83hs9s",
					EnvVarNameKey:    envKeyName,
					EnvVarNameSecret: envSecretName,
					HashAlg:          sha3.New384,
				},
			},
		},
		{
			name: "SHA3-512",
			envs: map[string]string{
				envKeyName:    "h480djs93hd8",
				envSecretName: "489dks293j39",
			},
			args: args{
				urlString: "http://example.com/resource/1?b=1&a=2",
				options: &MacHeaderOptions{
					Method:           "Get",
					Timestamp:        "1336363200",
					Nonce:            "dj83hs9s",
					EnvVarNameKey:    envKeyName,
					EnvVarNameSecret: envSecretName,
					HashAlg:          sha3.New512,
				},
			},
		},
		{
			name: "Whirlpool",
			envs: map[string]string{
				envKeyName:    "h480djs93hd8",
				envSecretName: "489dks293j39",
			},
			args: args{
				urlString: "http://example.com/resource/1?b=1&a=2",
				options: &MacHeaderOptions{
					Method:           "Get",
					Timestamp:        "1336363200",
					Nonce:            "dj83hs9s",
					EnvVarNameKey:    envKeyName,
					EnvVarNameSecret: envSecretName,
					HashAlg:          whirlpool.New,
				},
			},
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			keyEnvName := tt.args.options.EnvVarNameKey
			secretEnvName := tt.args.options.EnvVarNameSecret

			// store any previous value
			prevEnvKey := os.Getenv(keyEnvName)
			prevEnvSecret := os.Getenv(secretEnvName)
			// set test value
			os.Setenv(keyEnvName, tt.envs[envKeyName])
			os.Setenv(secretEnvName, tt.envs[envSecretName])
			// defer resetting to previous value
			defer os.Setenv(keyEnvName, prevEnvKey)
			defer os.Setenv(secretEnvName, prevEnvSecret)

			for i := 0; i < b.N; i++ {
				// Get on with it...
				MacHeaderString(tt.args.urlString, tt.args.options)
			}
		})
	}
}

func TestMacHeaderString(t *testing.T) {
	type args struct {
		urlString string
		options   *MacHeaderOptions
	}
	tests := []struct {
		name    string
		envs    map[string]string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "SHA-1 Example from IETF OAuth v2 HTTP MAC Draft 2",
			envs: map[string]string{
				envKeyName:    "h480djs93hd8",
				envSecretName: "489dks293j39",
			},
			args: args{
				urlString: "http://example.com/resource/1?b=1&a=2",
				options: &MacHeaderOptions{
					Method:           "Get",
					Timestamp:        "1336363200",
					Nonce:            "dj83hs9s",
					EnvVarNameKey:    envKeyName,
					EnvVarNameSecret: envSecretName,
					HashAlg:          sha256.New,
				},
			},
			want: `MAC id="h480djs93hd8", ts="1336363200", nonce="dj83hs9s", mac="1c0l2YIW7g7syyDmVHy2lxCeZK5VouDCuU0T0YOmTOU="`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyEnvName := tt.args.options.EnvVarNameKey
			secretEnvName := tt.args.options.EnvVarNameSecret

			// store any previous value
			prevEnvKey := os.Getenv(keyEnvName)
			prevEnvSecret := os.Getenv(secretEnvName)
			// set test value
			os.Setenv(keyEnvName, tt.envs[envKeyName])
			os.Setenv(secretEnvName, tt.envs[envSecretName])
			// defer resetting to previous value
			defer os.Setenv(keyEnvName, prevEnvKey)
			defer os.Setenv(secretEnvName, prevEnvSecret)

			myshit := map[string]string{
				"key":    os.Getenv(keyEnvName),
				"secret": os.Getenv(secretEnvName),
			}
			spew.Dump(myshit)

			// Get on with it...
			got, err := MacHeaderString(tt.args.urlString, tt.args.options)
			if (err != nil) != tt.wantErr {
				t.Errorf("MacHeaderString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("MacHeaderString()\n got = %v, \nwant = %v", got, tt.want)
			}
		})
	}
}

func TestSecret(t *testing.T) {
	type args struct {
		envVar string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := macauth.Secret(tt.args.envVar); got != tt.want {
				t.Errorf("Secret() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSign(t *testing.T) {
	type args struct {
		hashAlg func() hash.Hash
		card    *macauth.Card
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Sign(tt.args.hashAlg, tt.args.card)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Sign() got = %v, want %v", got, tt.want)
			}
		})
	}
}
