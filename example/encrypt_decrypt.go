package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"

	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/sirupsen/logrus"
	"github.com/twystd/tweetnacl-go/tweetnacl"
)

// DecryptPayload will decrypt a payload based on a key and nonce
func DecryptPayload(sharedKey []byte, encryptedPayload []byte, nonce []byte) []byte {
	var ret []byte
	if nonce == nil {
		nonce = emptyNounce
	}
	ret, err := tweetnacl.CryptoSecretBoxOpen(encryptedPayload, nonce, sharedKey)
	if err != nil {
		ret = emptyReturn
	}
	return ret
}

func serializeBytes(data []byte, buffer *bytes.Buffer) {
	tmp := make([]byte, 8)
	size := len(data)
	buffer.Grow(size + 8)
	binary.BigEndian.PutUint64(tmp, uint64(size))
	_, err := buffer.Write(tmp)
	if err != nil {
		logrus.WithError(err).Error("Could not write to buffer, serialization failed!")
	}
	_, err = buffer.Write(data)
	if err != nil {
		logrus.WithError(err).Error("Could not write to buffer, serialization failed!")
	}
}

var emptyReturn = []byte("")

// EncryptPayload will encrypt payload based on a key and nonce
func EncryptPayload(sharedKey []byte, payload []byte, nonce []byte) []byte {
	var ret []byte
	if nonce == nil {
		nonce = emptyNounce
	}
	ret, err := tweetnacl.CryptoSecretBox(payload, nonce, sharedKey)

	if err != nil {
		ret = emptyReturn
	}

	return ret
}

var ReadRandom = func(b []byte) (n int, err error) {
	return rand.Read(b)
}

// NewRandomKey generate new key
func NewRandomKey() ([]byte, error) {
	b := make([]byte, 32)
	_, err := ReadRandom(b)
	return b, err
}

// NewRandomNonce generate new nonce
func NewRandomNonce() ([]byte, error) {
	b := make([]byte, 24)
	_, err := ReadRandom(b)
	return b, err
}

var emptyNounce = []byte("\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000")

func main() {

	mnemonic := "tag volcano eight thank tide danger coast health above argue embrace heavy"

	wallet, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		log.Fatal(err)
	}

	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err := wallet.Derive(path, false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Account address: %s\n", account.Address.Hex())

	// publicKeyHex, _ := wallet.PublicKeyHex(account)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	privateKeyHex, err := wallet.PrivateKeyHex(account)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Input, Private key in hex: %s\n", privateKeyHex)

	privateKeyBytes, err := wallet.PrivateKeyBytes(account)
	if err != nil {
		log.Fatal(err)
	}

	//random sharedKey
	sharedKey, err := NewRandomKey()
	if err != nil {
		log.Fatal(err)
	}
	//nonce shared
	nonce, err := NewRandomNonce()
	if err != nil {
		log.Fatal(err)
	}

	buffer := bytes.NewBuffer([]byte{})

	cipher := EncryptPayload(sharedKey, privateKeyBytes, nonce)
	serializeBytes(cipher, buffer)

	ret, err := ioutil.ReadAll(buffer)
	if err != nil {
		logrus.WithError(err).Error("Could not read buffer, serialization failed!")
		ret = []byte{}
	}

	str := hex.EncodeToString(ret)

	fmt.Printf("Output ecrypted str: %s\n", str)

	privateKeyDecrypted := DecryptPayload(sharedKey, cipher, nonce)

	fmt.Printf("Output, Private key in hex: %s\n", hex.EncodeToString(privateKeyDecrypted))

}
