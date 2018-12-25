package pss_test

import (
	"testing"

	"github.com/westwin/pss"
)

func TestBcrypt(t *testing.T) {
	s := &pss.APS{Scheme: pss.Bcrypt}

	plain := "password"
	encoded, err := s.Encrypt(plain)
	if err != nil {
		t.Error(err)
	}

	t.Logf("%s is encoded to :%s", plain, encoded)

	if err := s.Verify(plain, encoded); err != nil {
		t.Error("does not match")
	}

	if err := s.Verify("wrongpassword", encoded); err == nil {
		t.Error("verify should fail")
	}
}

func TestBcryptSamePasswdGenerateDiffHash(t *testing.T) {
	s := &pss.APS{Scheme: pss.Bcrypt}

	plain := "password"
	encoded1, _ := s.Encrypt(plain)
	encoded2, _ := s.Encrypt(plain)

	if encoded1 == encoded2 {
		t.Error("same password should generate different hash")
	}

	err1 := s.Verify(plain, encoded1)
	if err1 != nil {
		t.Error("does not match")
	}

	err2 := s.Verify(plain, encoded2)
	if err2 != nil {
		t.Error("does not match")
	}
}
