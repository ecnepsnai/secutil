package secutil_test

import (
	"fmt"

	"github.com/ecnepsnai/secutil"
)

func ExampleHashingSHA_HashString() {
	input := "some secret data"
	result := secutil.Hashing.SHA_256.HashString(input)
	fmt.Printf("%s\n", result)
	// output: d61b9f52be1d066db55f392faf119d6a13302fdb7da80f62a9e5e9aa332f534b
}

func ExampleHashingBLAKE2_HashString() {
	input := "some secret data"
	result := secutil.Hashing.BLAKE2_256.HashString(input)
	fmt.Printf("%s\n", result)
	// output: d354690b768614c9bb4bf2ae367dc1b86cd3d6c1bd0ac6c281fe0c278bd8f2ae
}
