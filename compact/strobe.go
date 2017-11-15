package strobe

/***************************************************/
/*
/* This is a compact implementation of Strobe.
/* As it hasn't been thoroughly tested only use this
/* for experimental purposes :)
/*
/* Author: David Wong
/* Contact: www.cryptologie.net/contact
/*
/***************************************************/

import (
	"bytes"
	"encoding/binary"
)

// KEY inserts a key into the state.
// It also provides forward secrecy.
func (s *Strobe) KEY(key []byte) {
	s.operate(false, "KEY", key, 0, false)
}

// PRF provides a hash of length `output_len` of all previous operations
// It can also be used to generate random numbers, it is forward secure.
func (s *Strobe) PRF(outputLen int) []byte {
	return s.operate(false, "PRF", []byte{}, outputLen, false)
}

// Send_ENC_unauthenticated is used to encrypt some plaintext
// it should be followed by Send_MAC in order to protect its integrity
// `meta` is used for encrypted framing data.
func (s *Strobe) Send_ENC_unauthenticated(meta bool, plaintext []byte) []byte {
	return s.operate(meta, "send_ENC", plaintext, 0, false)
}

// Recv_ENC_unauthenticated is used to decrypt some received ciphertext
// it should be followed by Recv_MAC in order to protect its integrity
// `meta` is used for decrypting framing data.
func (s *Strobe) Recv_ENC_unauthenticated(meta bool, ciphertext []byte) []byte {
	return s.operate(meta, "recv_ENC", ciphertext, 0, false)
}

// AD allows you to authenticate Additional Data
// it should be followed by a Send_MAC or Recv_MAC in order to truly work
func (s *Strobe) AD(meta bool, additionalData []byte) {
	s.operate(meta, "AD", additionalData, 0, false)
}

// Send_CLR allows you to send data in cleartext
// `meta` is used to send framing data
func (s *Strobe) Send_CLR(meta bool, cleartext []byte) {
	s.operate(meta, "send_CLR", cleartext, 0, false)
}

// Recv_CLR allows you to receive data in cleartext.
// `meta` is used to receive framing data
func (s *Strobe) Recv_CLR(meta bool, cleartext []byte) {
	s.operate(meta, "recv_CLR", cleartext, 0, false)
}

// Send_MAC allows you to produce an authentication tag.
// `meta` is appropriate for checking the integrity of framing data.
func (s *Strobe) Send_MAC(meta bool, output_length int) []byte {
	return s.operate(meta, "send_MAC", []byte{}, output_length, false)
}

// Recv_MAC allows you to verify a received authentication tag.
// `meta` is appropriate for checking the integrity of framing data.
func (s *Strobe) Recv_MAC(meta bool, MAC []byte) bool {
	if s.operate(meta, "recv_MAC", MAC, 0, false)[0] == 0 {
		return true
	}
	return false
}

// RATCHET allows you to introduce forward secrecy in a protocol.
// It is similar to AES-GCM.
func (s *Strobe) RATCHET(length int) {
	s.operate(false, "RATCHET", []byte{}, length, false)
}

// Send_AEAD allows you to encrypt data and authenticate additional data
func (s *Strobe) Send_AEAD(plaintext, ad []byte) (ciphertext []byte) {
	ciphertext = append(ciphertext, s.Send_ENC_unauthenticated(false, plaintext)...)
	s.AD(false, ad)
	ciphertext = append(ciphertext, s.Send_MAC(false, MACLEN)...)
	return
}

// Recv_AEAD allows you to decrypt data and authenticate additional data
// It is similar to AES-GCM.
func (s *Strobe) Recv_AEAD(ciphertext, ad []byte) (plaintext []byte, ok bool) {
	if len(ciphertext) < MACLEN {
		ok = false
		return
	}
	plaintext = s.Recv_ENC_unauthenticated(false, ciphertext[:len(ciphertext)-MACLEN])
	s.AD(false, ad)
	ok = s.Recv_MAC(false, ciphertext[len(ciphertext)-MACLEN:])
	return
}

//
// Defining STROBE's security
//

const (
	strobeRate = 136
	// StrobeR is the blocksize of Strobe
	StrobeR = 134
	// MACLEN is the length of authentication tag created by Send_AEAD
	MACLEN = 16
)

//
// Strobe Objects
//

type role uint8 // for strobe.I0

const (
	iInitiator role = iota // set if we send the first transport message
	iResponder             // set if we receive the first transport message
	iNone                  // starting value
)

/*
  We do not use strobe's `pos` variable here since it is easily
  obtainable via `len(buf)`
*/
type Strobe struct {
	// strobe specific
	initialized bool  // used to avoid padding during the first permutation
	posBegin    uint8 // start of the current operation (0 := previous block)
	I0          role

	// streaming API
	curFlags flag

	// duplex construction (see sha3.go)
	a       [25]uint64
	buf     []byte
	rate    int
	storage [strobeRate]byte
}

// Clone allows you to clone a Strobe state.
func (s Strobe) Clone() *Strobe {

	ret := s
	ret.buf = ret.storage[:len(ret.buf)]
	return &ret
}

//
// Flags
//

type flag uint8

const (
	flagI flag = 1 << iota
	flagA
	flagC
	flagT
	flagM
	flagK
)

var operationMap = map[string]flag{
	"AD":       flagA,
	"KEY":      flagA | flagC,
	"PRF":      flagI | flagA | flagC,
	"send_CLR": flagA | flagT,
	"recv_CLR": flagI | flagA | flagT,
	"send_ENC": flagA | flagC | flagT,
	"recv_ENC": flagI | flagA | flagC | flagT,
	"send_MAC": flagC | flagT,
	"recv_MAC": flagI | flagC | flagT,
	"RATCHET":  flagC,
}

//
// Helper
//

/*
   we can't use Golang's sha3's functions here because they are
   expecting a sponge object. So we use these drop-in replacements:
*/

func xorState(state *[25]uint64, buf []byte) {
	n := len(buf) / 8
	for i := 0; i < n; i++ {
		a := binary.LittleEndian.Uint64(buf)
		state[i] ^= a
		buf = buf[8:]
	}
}

func outState(state [25]uint64, b []byte) {
	for i := 0; len(b) >= 8; i++ {
		binary.LittleEndian.PutUint64(b, state[i])
		b = b[8:]
	}
}

//
// Core functions
//

// InitStrobe allows you to initialize a new strobe instance.
func InitStrobe(customizationString string) (s Strobe) {

	s.I0 = iNone
	s.initialized = false
	domain := []byte{1, StrobeR + 2, 1, 0, 1, 12 * 8}
	domain = append(domain, []byte("STROBEv1.0.2")...)
	s.buf = s.storage[:0]
	s.duplex(domain, false, false, true)
	s.initialized = true
	s.operate(true, "AD", []byte(customizationString), 0, false)

	return
}

// runF: applies the STROBE's + cSHAKE's padding and the Keccak permutation
func (s *Strobe) runF() {
	if s.initialized {
		s.buf = append(s.buf, s.posBegin)
		s.buf = append(s.buf, 0x04)
		zerosStart := len(s.buf)
		s.buf = s.storage[:strobeRate]
		for i := zerosStart; i < strobeRate; i++ {
			s.buf[i] = 0
		}
		s.buf[strobeRate-1] ^= 0x80
	}

	keccakF1600(&s.a, 24)

	s.buf = s.storage[:0]
	s.posBegin = 0
}

// duplex: the duplex call
func (s *Strobe) duplex(data []byte, cbefore, cafter, forceF bool) {

	for len(data) > 0 {

		if len(s.buf) == 0 && len(data) >= StrobeR {
			if cbefore {
				var b [StrobeR]byte
				outState(s.a, b[:])
				for idx := 0; idx < StrobeR; idx++ {
					data[idx] ^= b[idx]
				}
			}

			xorState(&s.a, data[:StrobeR])

			if cafter {
				var b [StrobeR]byte
				outState(s.a, b[:])
				for idx := 0; idx < StrobeR; idx++ {
					data[idx] = b[idx]
				}
			}

			data = data[StrobeR:]

			s.runF()

		} else {

			todo := StrobeR - len(s.buf)
			if todo > len(data) { // is it too much?
				todo = len(data)
			}

			if cbefore {
				var b [StrobeR]byte
				outState(s.a, b[:])
				for idx, state := range b[len(s.buf) : len(s.buf)+todo] {
					data[idx] ^= state
				}
			}

			s.buf = append(s.buf, data[:todo]...)

			if cafter {
				var b [StrobeR]byte
				outState(s.a, b[:])
				for idx, state := range b[len(s.buf)-todo : len(s.buf)] {
					data[idx] ^= state
				}
			}

			data = data[todo:]

			if len(s.buf) == StrobeR {
				xorState(&s.a, s.buf)
				s.runF()
			}
		}
	}

	if forceF && len(s.buf) != 0 {
		zerosStart := len(s.buf)
		s.buf = s.storage[:strobeRate]
		for i := zerosStart; i < strobeRate; i++ {
			s.buf[i] = 0
		}

		xorState(&s.a, s.buf)
		s.runF()
	}

	return
}

// Operate: runs an operation (see OperationMap for a list of operations)
/*
  For operations that only require a length, provide the length via the
  length argument with an empty slice []byte{}. For other operations provide
  a zero length.
  Result is always retrieved through the return value. For boolean results,
  check that the first index is 0 for true, 1 for false.
*/
func (s *Strobe) operate(meta bool, operation string, dataConst []byte, length int, more bool) []byte {

	//
	// Operation checks
	//

	// operation is valid?
	var flags flag
	var ok bool
	if flags, ok = operationMap[operation]; !ok {
		panic("not a valid operation")
	}

	// operation is meta?
	if meta {
		flags |= flagM
	}

	// does the operation requires a length?
	var data []byte

	if (flags&(flagI|flagT) != (flagI | flagT)) && (flags&(flagI|flagA) != flagA) {

		if length == 0 {
			panic("A length should be set for this operation.")
		}

		data = bytes.Repeat([]byte{0}, length)

	} else {
		if length != 0 {
			panic("Output length must be zero except for PRF, send_MAC and RATCHET operations.")
		}

		data = make([]byte, len(dataConst))
		copy(data, dataConst)
	}

	// is this call the continuity of a previous call?
	if more {
		if flags != s.curFlags {
			panic("Flag should be the same when streaming operations.")
		}
	} else {
		s.beginOp(flags)
		s.curFlags = flags
	}

	// Operation
	cAfter := (flags & (flagC | flagI | flagT)) == (flagC | flagT)
	cBefore := (flags&flagC != 0) && (!cAfter)

	s.duplex(data, cBefore, cAfter, false)

	if (flags & (flagI | flagA)) == (flagI | flagA) {
		// Return data for the application
		return data
	} else if (flags & (flagI | flagT)) == flagT {
		// Return data for the transport.
		return data
	} else if (flags & (flagI | flagA | flagT)) == (flagI | flagT) {
		// Check MAC: all output bytes must be 0
		if more {
			panic("not supposed to check a MAC with the 'more' streaming option")
		}
		var failures byte
		for _, dataByte := range data {
			failures |= dataByte
		}
		return []byte{failures} // 0 if correct, 1 if not
	}

	// Operation has no output
	return nil
}

// beginOp: starts an operation
func (s *Strobe) beginOp(flags flag) {

	if flags&flagT != 0 {
		if s.I0 == iNone {
			s.I0 = role(flags & flagI)
		}
		flags ^= flag(s.I0)
	}

	oldBegin := s.posBegin
	s.posBegin = uint8(len(s.buf) + 1) // s.pos + 1
	forceF := (flags&(flagC|flagK) != 0)
	s.duplex([]byte{oldBegin, byte(flags)}, false, false, forceF)
}