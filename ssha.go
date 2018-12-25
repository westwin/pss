package pss

import (
	"bytes"
	"crypto/sha1"
)

// SSHA using a salted SHA-1 checksum of the data.
var SSHA = &Scheme{
	Name: "SSHA",
	Encrypter: func(plain []byte, args ...interface{}) ([]byte, error) {
		salt := generateSalt(sha1.Size)
		saltAndPlain := concatSlices(plain, salt)
		passwd := sha1.Sum(saltAndPlain)

		// concat salt and passwd together
		encoded := concatSlices(salt, passwd[:])

		return encoded, nil
	},
	Verifier: func(plain, encoded []byte, args ...interface{}) error {
		salt := encoded[:sha1.Size]
		passwd := encoded[sha1.Size:]

		saltAndPlain := concatSlices(plain, salt)
		e := sha1.Sum(saltAndPlain)

		if !bytes.Equal(passwd, e[:]) {
			return ErrPasswdNotMatch
		}
		return nil
	},
}

func init() {
	All.Register(SSHA)
}
