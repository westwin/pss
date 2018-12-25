package pss

// Plain stores password as plain text. This should be used for test only
var Plain = &Scheme{
	Name: "PLAIN",
	Encrypter: func(plain []byte, args ...interface{}) ([]byte, error) {
		return plain, nil
	},
	Verifier: func(plain, encoded []byte, args ...interface{}) error {
		if string(plain) == string(encoded) {
			return nil
		}

		return ErrPasswdNotMatch
	},
}
