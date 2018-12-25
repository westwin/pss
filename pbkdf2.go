package pss

import (
	"bytes"
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
)

const (
	defaultSaltLen    = 256
	defaultIterations = 10000
	defaultKeyLen     = 512
)

var defaultHashFunc = sha512.New

// PBKDF2 stores password with pbkdf2
var PBKDF2 = &Scheme{
	Name: "PBKDF2",
	Encrypter: func(plain []byte, args ...interface{}) ([]byte, error) {
		salt := generateSalt(defaultSaltLen)
		encodedPwd := pbkdf2.Key(plain, salt, defaultIterations, defaultKeyLen, defaultHashFunc)

		e := concatSlices(salt, encodedPwd)
		return e, nil
	},
	Verifier: func(plain, encoded []byte, args ...interface{}) error {
		salt := encoded[:defaultSaltLen]
		passwd := encoded[defaultSaltLen:]

		encodedPwd := pbkdf2.Key(plain, salt, defaultIterations, defaultKeyLen, defaultHashFunc)
		if bytes.Compare(passwd, encodedPwd) != 0 {
			return ErrPasswdNotMatch
		}
		return nil
	},
}

func init() {
	All.Register(PBKDF2)
}
