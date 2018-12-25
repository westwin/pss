package pss_test

import (
	"testing"

	"github.com/westwin/pss"
)

func TestDefaultScheme(t *testing.T) {
	plain := "password"
	encoded, err := pss.Encrypt(plain)
	if err != nil {
		t.Error(err)
	}

	t.Logf("%s is encoded to :%s", plain, encoded)
	t.Logf("password length:%d", len(encoded))

	if err := pss.Verify(plain, encoded); err != nil {
		t.Error("does not match")
	}

	if err := pss.Verify("wrongpassword", encoded); err == nil {
		t.Error("verify should fail")
	}
}

func TestVerifyDifferentSyntax(t *testing.T) {
	schemes := []*pss.APS{
		&pss.APS{Scheme: pss.SSHA512},
		&pss.APS{Scheme: pss.PBKDF2},
		&pss.APS{Scheme: pss.SSHA},
		&pss.APS{Scheme: pss.Bcrypt},
	}

	plain := "password"

	for _, s := range schemes {
		encoded, _ := s.Encrypt(plain)
		if err := pss.Verify(plain, encoded); err != nil {
			t.Errorf("does not match for scheme:%s", s.Scheme.Name)
		}

		if err := pss.Verify("wrongpassword", encoded); err == nil {
			t.Errorf("verify should fail for scheme:%s", s.Scheme.Name)
		}
	}
}

func TestUseDifferentDefaultScheme(t *testing.T) {
	pss.DefaultScheme = pss.SSHA.Name

	plain := "password"
	encoded, err := pss.Encrypt(plain)
	if err != nil {
		t.Error(err)
	}

	// use SSHA to verify the encoded password
	s := &pss.APS{Scheme: pss.SSHA}
	if err := s.Verify(plain, encoded); err != nil {
		t.Error("does not match")
	}
}
