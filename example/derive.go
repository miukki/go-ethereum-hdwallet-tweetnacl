package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"sync"

	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/sirupsen/logrus"
	"github.com/twystd/tweetnacl-go/tweetnacl"
)

var emptyReturns = []byte("")

var mutex = sync.RWMutex{}

var computedKeys = make(map[string][]byte)

var Read = func(b []byte) (n int, err error) {
	return rand.Read(b)
}

var ReadRandom2 = func(b []byte) (n int, err error) {
	return rand.Read(b)
}

// DecryptPayload2 will decrypt a payload based on a key and nonce
func DecryptPayload2(sharedKey []byte, encryptedPayload []byte, nonce []byte) []byte {
	var ret []byte
	if nonce == nil {
		nonce = []byte("\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000")
	}
	ret, err := tweetnacl.CryptoSecretBoxOpen(encryptedPayload, nonce, sharedKey)
	if err != nil {
		ret = []byte("")
	}
	return ret
}

// NewRandomNonce generate new nonce
func NewRandomNonce2() ([]byte, error) {
	b := make([]byte, 24)
	_, err := ReadRandom2(b)
	return b, err
}

// EncryptPayload will encrypt payload based on a key and nonce
func EncryptPayload2(sharedKey []byte, payload []byte, nonce []byte) []byte {
	var ret []byte
	if nonce == nil {
		nonce = []byte("\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000")
	}
	ret, err := tweetnacl.CryptoSecretBox(payload, nonce, sharedKey)

	if err != nil {
		ret = []byte("")
	}

	return ret
}

func serializeBytes2(data []byte, buffer *bytes.Buffer) {
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

func main() {
	mnemonic := "tag volcano eight thank tide danger coast health above argue embrace heavy"
	wallet, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		log.Fatal(err)
	}

	//nonce shared
	nonce, err := NewRandomNonce2()
	buffer := bytes.NewBuffer([]byte{})

	if err != nil {
		log.Fatal(err)
	}

	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account1, err := wallet.Derive(path, false)
	if err != nil {
		log.Fatal(err)
	}

	publicKeyBytes1, _ := wallet.PublicKeyBytes(account1)
	if err != nil {
		log.Fatal(err)
	}

	privateKeyHex1, err := wallet.PrivateKeyHex(account1)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("account1.Address.Hex()", account1.Address.Hex())
	fmt.Println("account1.Address.Hash().Bytes()", account1.Address.Hash().Bytes())
	fmt.Printf("privateKeyHex1: %s\n", privateKeyHex1)
	fmt.Println("publicKeyBytes1", publicKeyBytes1)

	privateKeyBytes1, err := wallet.PrivateKeyBytes(account1)
	if err != nil {
		log.Fatal(err)
	}

	path = hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/1")
	account2, err := wallet.Derive(path, false)
	if err != nil {
		log.Fatal(err)
	}

	publicKeyBytes2, _ := wallet.PublicKeyBytes(account2)
	if err != nil {
		log.Fatal(err)
	}

	privateKeyHex2, err := wallet.PrivateKeyHex(account2)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("account1.Address.Hash().Bytes()", account2.Address.Hash().Bytes())
	fmt.Println("account2.Address.Hex()", account2.Address.Hex())
	fmt.Printf("privateKeyHex2: %s\n", privateKeyHex2)
	fmt.Println("publicKeyBytes2", publicKeyBytes2)

	privateKeyBytes2, err := wallet.PrivateKeyBytes(account2)
	if err != nil {
		log.Fatal(err)
	}

	sharedKey1, err := tweetnacl.CryptoBoxBeforeNM(account2.Address.Hash().Bytes(), privateKeyBytes1)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(`sharedKey1`, sharedKey1)

	sharedKey2, err := tweetnacl.CryptoBoxBeforeNM(account1.Address.Hash().Bytes(), privateKeyBytes2)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(`sharedKey2`, sharedKey2)

	//test sharedKey1
	fmt.Printf("encrypting privateKeyHex1 with sharedKey2...: %s\n", privateKeyHex1)

	cipher := EncryptPayload2(sharedKey2, privateKeyBytes1, nonce)

	serializeBytes2(cipher, buffer)

	ret, err := ioutil.ReadAll(buffer)
	if err != nil {
		logrus.WithError(err).Error("Could not read buffer, serialization failed!")
		ret = []byte{}
	}

	str := hex.EncodeToString(ret)

	fmt.Printf("Output ecrypted str: %s\n", str)

	privateKeyDecrypted := DecryptPayload2(sharedKey2, cipher, nonce)

	fmt.Printf("decrypting privateKeyHex1 with sharedKey2: %s\n", hex.EncodeToString(privateKeyDecrypted))

}
