package strobe

import (
	"encoding/hex"
	"testing"
)

var message = []byte("hello, how are you good sir?")

func TestClone(t *testing.T) {

	s1 := InitStrobe("myHash", 128)
	s2 := s1.Clone()

	s1.Operate(false, "AD", message, 0, false)
	out1 := hex.EncodeToString(s1.PRF(32))

	s2.Operate(false, "AD", message, 0, false)
	out2 := hex.EncodeToString(s2.PRF(32))

	if out1 != out2 {
		t.Fatal("strobe cannot clone correctly")
	}

	s1.Operate(false, "send_ENC", message, 0, false)
	out1 = hex.EncodeToString(s1.PRF(32))

	s2.Operate(false, "send_ENC", message, 0, false)
	out2 = hex.EncodeToString(s2.PRF(32))

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

	if out1 != out2 {
		t.Fatal("strobe cannot stream correctly")
	}
}

func TestStream2(t *testing.T) {
	s := InitStrobe("custom string number 2, that's a pretty long string", 128)
	key := []byte("0101010100100101010101010101001001")
	s.Operate(false, "KEY", key, 0, false)
	s.Operate(false, "KEY", key, 0, true)
	message := []byte("hello, how are you good sir? ????")
	s.Operate(false, "AD", message, 0, false)
	s.Operate(false, "AD", message, 0, true)
	s.Operate(false, "AD", message, 0, false)
	if s.debugPrintState() != "5117b46c2d842655c1be2a69f64f16aaaad2c0050fe2ac5446afe44345a9b10d044c8b3ec8005a9e362c0a431ab5c4d8228c2f890ae56ad3fef4404aa6cc76704b503d627553ae9635d329cdfa86ed29ec0dd79787ff3fcefdee7463c053ef3b4a4fa7c8eb89a6372df2c4ccfc7469d7447bd19a67940642334706e5ff6b1ef58514e55c6b5c6921c58eb7cb5c57978c92c42e598926fcfdcd9705fb948ed6fe9027c65fb0659c98a9c9668d523dfa2b27bde76224944503b686901c989fedac34994dd16daedf00" {
		t.Fatal("this is not working")
	}
}

func TestRecover(t *testing.T) {
	s := InitStrobe("custom string number 2, that's a pretty long string", 128)
	key := []byte("0101010100100101010101010101001001")
	s.Operate(false, "KEY", key, 0, false)
	s.Operate(false, "KEY", key, 0, true)

	// serialize and clone
	cloned := s.Clone()
	serialized := s.Serialize()

	// recover
	recovered := RecoverState(serialized)

	// and compare recovered and cloned
	recovered.Operate(false, "send_ENC", message, 0, false)
	out1 := hex.EncodeToString(recovered.PRF(32))

	cloned.Operate(false, "send_ENC", message, 0, false)
	out2 := hex.EncodeToString(cloned.PRF(32))

	if out1 != out2 {
		t.Fatal("strobe cannot serialize/recover correctly")
	}

	recovered.Operate(false, "send_MAC", []byte{}, 16, false)
	out1 = hex.EncodeToString(recovered.PRF(32))

	cloned.Operate(false, "send_MAC", []byte{}, 16, false)
	out2 = hex.EncodeToString(cloned.PRF(32))

	if out1 != out2 {
		t.Fatal("strobe cannot serialize/recover correctly")
	}
}
