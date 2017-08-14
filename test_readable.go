package main

import (
	"bytes"
	"fmt"

	strobe "./readable"
)

// testing a simple hash function
func test_hash() {
	s1 := strobe.InitStrobe("davidwonghash")
	s2 := strobe.InitStrobe("davidwonghash")

	message := []byte("message to be hashed")

	s1.AD(false, message)
	s2.AD(false, message)

	hash1 := s1.PRF(32)
	hash2 := s2.PRF(32)

	if bytes.Equal(hash1, hash2) {
		fmt.Println("hashes are equal :)")
	} else {
		fmt.Println("hashes are not equal :(")
	}

	fmt.Println("hash1:", hash1)
	fmt.Println("hash2:", hash2)

}

// testing an encryption/decryption protocol
func test_enc_dec() {

	fmt.Println("==ENCRYPTION PROTOCOL TEST==")

	// init
	s_client := strobe.InitStrobe("davidwongencryption")
	s_server := strobe.InitStrobe("davidwongencryption")

	// keys
	sharedKey := bytes.Repeat([]byte{1}, 134)
	s_client.KEY(sharedKey)
	s_server.KEY(sharedKey)

	// encrypt + mac
	fmt.Println("==CLIENT ENCRYPT==")

	message := []byte("salut")
	ciphertext := s_client.Send_ENC(false, message)
	fmt.Println("ciphertext:", ciphertext)
	mac := s_client.Send_MAC(false, 32)
	fmt.Println("mac:", mac)

	// decrypt + mac
	strobe.Verbose = true
	fmt.Println("==SERVER DECRYPT==")

	plaintext := s_server.Recv_ENC(false, ciphertext)
	valid := s_server.Recv_MAC(false, mac)

	if valid {
		fmt.Println("plaintext:", string(plaintext))
	} else {
		fmt.Println("mac invalid, result:", valid, " plaintext:", string(plaintext))
	}
}

func test_empty_plaintext(){
	s_client := strobe.InitStrobe("davidwongencryption")
	s_server := strobe.InitStrobe("davidwongencryption")
	// keys
	sharedKey := bytes.Repeat([]byte{1}, 134)
	s_client.KEY(sharedKey)
	s_server.KEY(sharedKey)

	ciphertext := s_client.Send_AEAD([]byte{}, []byte{})
	fmt.Println(ciphertext)

	plaintext, ok := s_server.Recv_AEAD(ciphertext, []byte{})
	fmt.Println(ok, plaintext)
}

func main() {
	//test_hash()
	//test_enc_dec()
	test_empty_plaintext()
}
