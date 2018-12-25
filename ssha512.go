package pss

import (
	"bytes"
	"crypto/sha512"
)

// SSHA512 using a salted 512-bit version of SHa-2 Secure Hash Algorithm
var SSHA512 = &Scheme{
	Name: "SSHA512",
	Encrypter: func(plain []byte, args ...interface{}) ([]byte, error) {
		salt := generateSalt(sha512.Size)
		saltAndPlain := concatSlices(plain, salt)
		passwd := sha512.Sum512(saltAndPlain)

		// concat salt and passwd together
		encoded := concatSlices(salt, passwd[:])

		return encoded, nil
	},
	Verifier: func(plain, encoded []byte, args ...interface{}) error {
		salt := encoded[:sha512.Size]
		passwd := encoded[sha512.Size:]

		saltAndPlain := concatSlices(plain, salt)
		e := sha512.Sum512(saltAndPlain)

		if !bytes.Equal(passwd, e[:]) {
			return ErrPasswdNotMatch
		}
		return nil
	},
}

func init() {
	All.Register(SSHA512)
}
