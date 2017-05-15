package main

import(
	"golang.org/x/crypto/sha3"
	"fmt"
	"bytes"
)

// testing a simple hash function
func test_hash() {
	s1 := sha3.InitStrobe("davidwonghash")
	s2 := sha3.InitStrobe("davidwonghash")

	message := []byte("message to be hashed")

	s1.Operate(false, "AD", message, 0, false)
	s2.Operate(false, "AD", message, 0, false)

	hash1 := s1.Operate(false, "PRF", []byte{}, 32, false)
	hash2 := s2.Operate(false, "PRF", []byte{}, 32, false)

	if bytes.Equal(hash1, hash2) {
		fmt.Println("hashes are equal :)")
	} else {
		fmt.Println("hashes are not equal :(")
	}

	fmt.Println("hash1:", hash1)
	fmt.Println("hash2:", hash2)

}

// testing an encryption/decryption protocol
func test_enc_dec(){
	
	fmt.Println("==ENCRYPTION PROTOCOL TEST==")

	// init
	s_client := sha3.InitStrobe("davidwongencryption")
	s_server := sha3.InitStrobe("davidwongencryption")

	// keys
	shared_key := bytes.Repeat([]byte{1}, 134)
	s_client.Operate(false, "KEY", shared_key, 0, false)
	s_server.Operate(false, "KEY", shared_key, 0, false)

	// encrypt + mac
	fmt.Println("==CLIENT ENCRYPT==")

	message := []byte("salut")
	ciphertext := s_client.Operate(false, "send_ENC", message, 0, false)
	fmt.Println("ciphertext:", ciphertext)
	mac := s_client.Operate(false, "send_MAC", []byte{}, 32, false)
	fmt.Println("mac:", mac)

	// decrypt + mac
	sha3.Verbose = true
	fmt.Println("==SERVER DECRYPT==")
	
	plaintext := s_server.Operate(false, "recv_ENC", ciphertext, 0, false)
	valid := s_server.Operate(false, "recv_MAC", mac, 0, false)

	if valid[0] == 0 {
		fmt.Println("plaintext:", string(plaintext))
	} else {
		fmt.Println("mac invalid")
	}
}

func main(){
	//test_hash()
	test_enc_dec()
}
