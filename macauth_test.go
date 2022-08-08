package macauth

import (
	"testing"
)

func TestNow(t *testing.T) {
	want := 10
	got := len(Now())

	if want != got {
		t.Errorf("expected Now() to return a 10 digit string")
	}
}

func TestRandHex(t *testing.T) {
	want := 32
	h, err := RandHex()
	if err != nil {
		t.Errorf("expected RandHex() not to return an error")
	}
	got := len(h)

	if want != got {
		t.Errorf("expected RandHex() to return 32 characters of hex")
	}
}
