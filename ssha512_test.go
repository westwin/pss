package pss_test

import (
	"testing"

	"github.com/westwin/pss"
)

func TestSSHA512(t *testing.T) {
	s := &pss.APS{Scheme: pss.SSHA512}

	plain := "password"
	encoded, err := s.Encrypt(plain)
	if err != nil {
		t.Error(err)
	}

	t.Logf("%s is encoded to :%s", plain, encoded)
	t.Logf("password length:%d", len(encoded))

	if err := s.Verify(plain, encoded); err != nil {
		t.Error("does not match")
	}

	if err := s.Verify("wrongpassword", encoded); err == nil {
		t.Error("verify should fail")
	}
}

func TestSSHA512SamePasswdGenerateDiffHash(t *testing.T) {
	s := &pss.APS{Scheme: pss.SSHA512}

	plain := "password"
	encoded1, _ := s.Encrypt(plain)
	encoded2, _ := s.Encrypt(plain)

	if encoded1 == encoded2 {
		t.Error("same password should generate different encoded password")
	}

	if err := s.Verify(plain, encoded1); err != nil {
		t.Error("does not match")
	}

	if err := s.Verify(plain, encoded2); err != nil {
		t.Error("does not match")
	}
}
