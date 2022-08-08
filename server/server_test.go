package server

import "testing"

func BenchmarkNewSecret(b *testing.B) {
	type arg struct {
		name string
		arg  int
	}

	benchmarks := []arg{
		{
			name: "16",
			arg:  16,
		},
		{
			name: "64",
			arg:  64,
		},
		{
			name: "256",
			arg:  256,
		},
		{
			name: "512",
			arg:  512,
		},
		{
			name: "1024",
			arg:  1024,
		},
		{
			name: "2048",
			arg:  2048,
		},
		{
			name: "4096",
			arg:  4096,
		},
	}

	for _, a := range benchmarks {
		b.Run(a.name, func(bb *testing.B) {
			for i := 0; i < bb.N; i++ {
				NewSecret(a.arg)
			}
		})
	}
}

func TestNewSecret(t *testing.T) {
	type args struct {
		randLength int
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "happy path - 0",
			args:    args{randLength: 0},
			want:    "",
			wantErr: false,
		},
		{
			name:    "happy path - 64",
			args:    args{randLength: 64},
			want:    "",
			wantErr: false,
		},
		{
			name:    "happy path - 4096",
			args:    args{randLength: 4096},
			want:    "",
			wantErr: false,
		},
		{
			name:    "happy path - negative",
			args:    args{randLength: -13},
			want:    "",
			wantErr: false,
		},
		{
			name:    "expected fail; randLength = 313 (non-power of 2, odd)",
			args:    args{randLength: 313},
			want:    "",
			wantErr: true,
		},
		{
			name:    "expected fail; randLength = 386 (non-power of 2, even)",
			args:    args{randLength: 386},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSecret(tt.args.randLength)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NewSecret()\n got = '%v', \nwant = '%v'", got, tt.want)
			}
		})
	}
}
