package pss

import (
	"bytes"
	"crypto/sha256"
)

// SSHA256 using a salted 256-bit version of SHa-2 Secure Hash Algorithm
var SSHA256 = &Scheme{
	Name: "SSHA256",
	Encrypter: func(plain []byte, args ...interface{}) ([]byte, error) {
		salt := generateSalt(sha256.Size)
		saltAndPlain := concatSlices(plain, salt)
		passwd := sha256.Sum256(saltAndPlain)

		// concat salt and passwd together
		encoded := concatSlices(salt, passwd[:])

		return encoded, nil
	},
	Verifier: func(plain, encoded []byte, args ...interface{}) error {
		salt := encoded[:sha256.Size]
		passwd := encoded[sha256.Size:]

		saltAndPlain := concatSlices(plain, salt)
		e := sha256.Sum256(saltAndPlain)

		if !bytes.Equal(passwd, e[:]) {
			return ErrPasswdNotMatch
		}
		return nil
	},
}

func init() {
	All.Register(SSHA256)
}
