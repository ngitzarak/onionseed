package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/sha3"
)

func generate(seed []byte) {

	//reader := strings.NewReader(seed)
	//chunk := extrapolate(seed, n+1)
	reader := bytes.NewReader(seed)

	publicKey, secretKey, err := ed25519.GenerateKey(reader)
	checkErr(err)

	onionAddress := encodePublicKey(publicKey)

	fmt.Println(onionAddress)
	save(onionAddress, publicKey, expandSecretKey(secretKey))
}

func expandSecretKey(secretKey ed25519.PrivateKey) [64]byte {

	hash := sha512.Sum512(secretKey[:32])
	hash[0] &= 248
	hash[31] &= 127
	hash[31] |= 64
	return hash

}

func encodePublicKey(publicKey ed25519.PublicKey) string {

	// checksum = H(".onion checksum" || pubkey || version)
	var checksumBytes bytes.Buffer
	checksumBytes.Write([]byte(".onion checksum"))
	checksumBytes.Write([]byte(publicKey))
	checksumBytes.Write([]byte{0x03})
	checksum := sha3.Sum256(checksumBytes.Bytes())

	// onion_address = base32(pubkey || checksum || version)
	var onionAddressBytes bytes.Buffer
	onionAddressBytes.Write([]byte(publicKey))
	onionAddressBytes.Write([]byte(checksum[:2]))
	onionAddressBytes.Write([]byte{0x03})
	onionAddress := base32.StdEncoding.EncodeToString(onionAddressBytes.Bytes())

	return strings.ToLower(onionAddress)

}

func save(onionAddress string, publicKey ed25519.PublicKey, secretKey [64]byte) {
	os.MkdirAll(onionAddress, 0700)

	secretKeyFile := append([]byte("== ed25519v1-secret: type0 ==\x00\x00\x00"), secretKey[:]...)
	checkErr(ioutil.WriteFile(onionAddress+"/hs_ed25519_secret_key", secretKeyFile, 0600))

	publicKeyFile := append([]byte("== ed25519v1-public: type0 ==\x00\x00\x00"), publicKey...)
	checkErr(ioutil.WriteFile(onionAddress+"/hs_ed25519_public_key", publicKeyFile, 0600))

	checkErr(ioutil.WriteFile(onionAddress+"/hostname", []byte(onionAddress+".onion"), 0600))
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	seed, err := base64.StdEncoding.DecodeString(os.Args[1])
	if err != nil {
		panic(err)
	}
	generate(seed)

}
