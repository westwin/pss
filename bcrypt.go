package pss

import "golang.org/x/crypto/bcrypt"

// Bcrypt stores password as bcypt hash.
var Bcrypt = &Scheme{
	Name: "BCRYPT",
	Encrypter: func(plain []byte, args ...interface{}) ([]byte, error) {
		return bcrypt.GenerateFromPassword(plain, bcrypt.DefaultCost)
	},
	Verifier: func(plain, encoded []byte, args ...interface{}) error {
		return bcrypt.CompareHashAndPassword(encoded, plain)
	},
}

func init() {
	All.Register(Bcrypt)
}
