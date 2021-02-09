package secutil_test

import (
	"fmt"

	"github.com/ecnepsnai/secutil"
)

func ExampleHashPassword() {
	password := []byte("hunter2")
	hashedPassword, err := secutil.HashPassword(password)
	if err != nil {
		panic(err)
	}

	// hashedPassword contains the algorithm used, the salt, and the hash data. It is safe for storage.
	fmt.Printf("%s\n", *hashedPassword)
}

func ExampleHashedPassword_Compare() {
	password := []byte("hunter2")
	hashedPassword, err := secutil.HashPassword(password)
	if err != nil {
		panic(err)
	}

	test1 := hashedPassword.Compare([]byte("hunter1"))
	test2 := hashedPassword.Compare([]byte("hunter2"))
	test3 := hashedPassword.Compare([]byte("hunter3"))

	fmt.Printf("Password is 'hunter1': %v, Password is 'hunter2': %v, Password is 'hunter3': %v\n", test1, test2, test3)

	// output: Password is 'hunter1': false, Password is 'hunter2': true, Password is 'hunter3': false
}
