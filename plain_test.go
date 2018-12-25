package pss_test

import (
	"testing"

	"github.com/westwin/pss"
)

func TestPlain(t *testing.T) {
	s := &pss.APS{Scheme: pss.Plain}

	plain := "password"
	encoded, err := s.Encrypt(plain)
	if err != nil {
		t.Error(err)
	}

	if err := s.Verify(plain, encoded); err != nil {
		t.Error("does not match")
	}

	if err := s.Verify("wrongpassword", encoded); err == nil {
		t.Error("verify should fail")
	}
}
