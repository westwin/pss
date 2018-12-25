// Package pss provides some Password Storage Schemes which is defined in https://tools.ietf.org/html/rfc3112
package pss

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// common errors
var (
	ErrPasswdNotMatch = errors.New("password not matching")
	ErrInvalidSyntax  = errors.New("invalid password storage syntax")
	ErrUnknownScheme  = errors.New("unknown password storage scheme")
)

// Scheme represents Password Storage Scheme
// which is described in https://tools.ietf.org/html/rfc3112
type Scheme struct {
	Name      string // Scheme name, Must be 0-9, A-Z, "-", ".", "/", or "_"
	Encrypter func(plain []byte, args ...interface{}) ([]byte, error)
	Verifier  func(plain, encoded []byte, args ...interface{}) error // nil for matching
}

// APS represents authentication password syntax, see rfc3112
type APS struct {
	Scheme *Scheme
}

// Encrypt encrypts the plain text password to encoded password in authPassword syntax
func (s *APS) Encrypt(plain string, args ...interface{}) (string, error) {
	encrypted, err := s.Scheme.Encrypter([]byte(plain), args)
	if err != nil {
		return "", err
	}

	encoded := s.encode(encrypted)
	return fmt.Sprintf("{%s}%s", s.Scheme.Name, encoded), nil
}

// Verify verify the plain password matches the encoded one, return nil for matching
func (s *APS) Verify(plain, encoded string, args ...interface{}) error {
	schemeName, encodedPasswd, err := parse(encoded)
	if err != nil {
		return errors.New("password invalid encoding format")
	}

	if normalizeName(schemeName) != normalizeName(s.Scheme.Name) {
		return errors.New("the scheme of encoded password does not match")
	}

	decodedPasswd, err := s.decode(encodedPasswd)
	if err != nil {
		return errors.New("password invalid encoding format")
	}

	return s.Scheme.Verifier([]byte(plain), decodedPasswd)
}

func (s *APS) encode(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func (s *APS) decode(str string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(str)
}

// Schemes is a APS array
type Schemes map[string]*APS

// All includes all supported password storage scheme
var All = make(Schemes, 1)

// DefaultScheme is the name of default password storage scheme
var DefaultScheme = "BCRYPT"

// Register a new scheme
func (ss *Schemes) Register(s *Scheme) {
	if s.Name == "" {
		return
	}

	(*ss)[normalizeName(s.Name)] = &APS{
		Scheme: s,
	}
}

// Unregister a scheme
func (ss *Schemes) Unregister(name string) {
	delete(*ss, normalizeName(name))
}

// Get returns a named scheme
func (ss *Schemes) Get(name string) (*APS, bool) {
	s, ok := (*ss)[normalizeName(name)]
	return s, ok
}

// Encrypt the password with default password storage scheme
func (ss *Schemes) Encrypt(plain string, args ...interface{}) (string, error) {
	s, ok := ss.Get(DefaultScheme)
	if !ok {
		return "", ErrUnknownScheme
	}
	return s.Encrypt(plain, args)
}

// Verify the encoded password, return nil for success
func (ss *Schemes) Verify(plain, encoded string, args ...interface{}) error {
	name, _, err := parse(encoded)
	if err != nil {
		return err
	}
	s, ok := ss.Get(name)
	if !ok {
		return ErrUnknownScheme
	}

	return s.Verify(plain, encoded, args)
}

// Encrypt the password
func Encrypt(plain string, args ...interface{}) (string, error) {
	return All.Encrypt(plain, args)
}

// Verify the encoded password, return nil for success
func Verify(plain, encoded string, args ...interface{}) error {
	return All.Verify(plain, encoded, args)
}

// Parse the encoded password to scheme name and password
func parse(encoded string) (string, string, error) {
	i := strings.Index(encoded, "}")
	if i == -1 {
		return "", "", ErrInvalidSyntax
	}
	schemeName := encoded[1:i]
	passwd := encoded[i+1:]
	return schemeName, passwd, nil
}

// RFC3112 needs scheme name be upper case.
func normalizeName(name string) string {
	return strings.ToUpper(name)
}

func generateSalt(length int) []byte {
	salt := make([]byte, length)
	rand.Read(salt)
	return salt
}

func concatSlices(src ...[]byte) []byte {
	dst := make([]byte, 0)
	for _, s := range src {
		dst = append(dst, s...)
	}
	return dst
}
