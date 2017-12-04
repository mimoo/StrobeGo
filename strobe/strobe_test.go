package strobe

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestClone(t *testing.T) {
	message := []byte("hello, how are you good sir?")

	s1 := InitStrobe("myHash", 128)
	s2 := s1.Clone()

	s1.Operate(false, "AD", message, 0, false)
	out1 := hex.EncodeToString(s1.PRF(32))

	s2.Operate(false, "AD", message, 0, false)
	out2 := hex.EncodeToString(s2.PRF(32))

	if out1 != out2 {
		t.Fatal("strobe cannot clone correctly")
	}
}

func TestStream(t *testing.T) {
	message1 := "hello"
	message2 := "how are you good sir?"
	fullmessage := message1 + message2

	s1 := InitStrobe("myHash", 128)
	s2 := s1.Clone()

	s1.Operate(false, "AD", []byte(fullmessage), 0, false)
	out1 := hex.EncodeToString(s1.PRF(32))

	s2.Operate(false, "AD", []byte(message1), 0, false)
	s2.Operate(false, "AD", []byte(message2), 0, true)
	out2 := hex.EncodeToString(s2.PRF(32))

	fmt.Println(out1)
	fmt.Println(out2)

	if out1 != out2 {
		t.Fatal("strobe cannot stream correctly")
	}
}
