package strobe

/***************************************************/
/*
/* This is a "readable" implementation of Strobe.
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

//
// Debug
//

var Verbose bool

//
// Not so necessary High level APIs
//

// inserts a key into the state
func (s *Strobe) KEY(key []byte) {
	s.operate(false, "KEY", key, 0, false)
}

// provides a hash of length `output_len` of all previous operations
func (s *Strobe) PRF(output_len int) []byte {
	return s.operate(false, "PRF", []byte{}, output_len, false)
}

// `meta` is used for encrypted framing data.
func (s *Strobe) Send_ENC(meta bool, plaintext []byte) []byte {
	return s.operate(meta, "send_ENC", plaintext, 0, false)
}

// `meta` is used for decrypting framing data.
func (s *Strobe) Recv_ENC(meta bool, ciphertext []byte) []byte {
	return s.operate(meta, "recv_ENC", ciphertext, 0, false)
}

// Additional Data
func (s *Strobe) AD(meta bool, additionalData []byte) {
	s.operate(meta, "AD", additionalData, 0, false)
}

// `meta` is used to send framing data
func (s *Strobe) Send_CLR(meta bool, cleartext []byte) {
	s.operate(meta, "send_CLR", cleartext, 0, false)
}

// `meta` is used to receive framing data
func (s *Strobe) Recv_CLR(meta bool, cleartext []byte) {
	s.operate(meta, "recv_CLR", cleartext, 0, false)
}

// `meta` is appropriate for checking the integrity of framing data.
func (s *Strobe) Send_MAC(meta bool, output_length int) []byte {
	return s.operate(meta, "send_MAC", []byte{}, output_length, false)
}

// `meta` is appropriate for checking the integrity of framing data.
func (s *Strobe) Recv_MAC(meta bool, MAC []byte) bool {
	if s.operate(meta, "recv_MAC", MAC, 0, false)[0] == 0 {
		return true
	}
	return false
}

//
func (s *Strobe) RATCHET(length int) {
	s.operate(false, "RATCHET", []byte{}, length, false)
}

//
// Defining STROBE's security
//

const (
	strobe_b    = 1600 // rate+capacity of the permutation
	strobe_N    = 200  // b/8 (rate+capacity in bytes)
	strobe_sec  = 256  // 256-bit of security
	strobe_rate = 136
	strobe_R    = 134 // N - (2*sec)/8 - 2
/*
  R (the block size) is the rate minus the strobe padding (1 byte) and
  the cSHAKE padding (1 byte)
*/
)

//
// Strobe Objects
//

type role uint8 // for strobe.I0

const (
	i_none      role = 2 // starting value
	i_initiator role = 0 // set if we send the first transport message
	i_responder role = 1 // set if we receive the first transport message
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
	cur_flags flag

	// duplex construction (see sha3.go)
	a       [25]uint64
	buf     []byte
	rate    int
	storage [strobe_rate]byte
}

func (s *Strobe) Clone() Strobe {

	ret := *s
	ret.buf = ret.storage[:len(ret.buf)]
	return ret
}

//
// Flags
//

type flag uint8

var flagMap = map[rune]uint8{'I': 0, 'A': 1, 'C': 2, 'T': 3, 'M': 4, 'K': 5}

var I flag = 1 << flagMap['I']
var A flag = 1 << flagMap['A']
var C flag = 1 << flagMap['C']
var T flag = 1 << flagMap['T']
var M flag = 1 << flagMap['M']
var K flag = 1 << flagMap['K']

var operationMap = map[string]flag{
	"AD":       A,
	"KEY":      A | C,
	"PRF":      I | A | C,
	"send_CLR": A | T,
	"recv_CLR": I | A | T,
	"send_ENC": A | C | T,
	"recv_ENC": I | A | C | T,
	"send_MAC": C | T,
	"recv_MAC": I | C | T,
	"RATCHET":  C,
}

func (f *flag) add(letters string) {
	for _, letter := range letters {
		offset, ok := flagMap[letter]
		if ok {
			*f ^= 1 << offset
		}
	}
}

func (f *flag) contains(letters string) bool {
	for _, letter := range letters {
		if offset := flagMap[letter]; *f&(1<<offset) == 0 {
			return false
		}
	}
	return true
}

func (f *flag) toggle(letters string) {
	for _, letter := range letters {
		*f ^= 1 << flagMap[letter]
	}
}

func (f *flag) toString() (flag string) {

	for letter, offset := range flagMap {
		if *f&(1<<offset) != 0 {
			flag += string(letter)
		}
	}
	return
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

// Initialize a new strobe instance
func InitStrobe(customizationString string) (s Strobe) {

	/*
	  // Go already set these values to zero
	  s.posBegin = 0
	  s.cur_flags = 0
	*/
	s.I0 = i_none
	s.initialized = false
	domain := []byte{1, strobe_R + 2, 1, 0, 1, 12 * 8}
	domain = append(domain, []byte("STROBEv1.0.2")...)

	// init duplex construction
	s.buf = s.storage[:0]

	// run the permutation
	s.duplex(domain, false, false, true)
	s.initialized = true

	// run the customization string in META mode
	s.operate(true, "AD", []byte(customizationString), 0, false)

	//
	return
}

// runF: applies the STROBE's + cSHAKE's padding and the Keccak permutation
func (s *Strobe) runF() {
	/*
	   we do not run this padding during Strobe's initialization.
	   This allow us to respect cSHAKE's specification.
	*/
	if s.initialized {
		// STROBE's padding
		s.buf = append(s.buf, s.posBegin)
		// cSHAKE's padding
		s.buf = append(s.buf, 0x04)
		// zeros
		zerosStart := len(s.buf)
		s.buf = s.storage[:strobe_rate]
		for i := zerosStart; i < strobe_rate; i++ {
			s.buf[i] = 0
		}
		// final bit
		s.buf[strobe_rate-1] ^= 0x80
	}

	// permutation
	keccakF1600(&s.a, 24)

	// init new block
	s.buf = s.storage[:0] //  s.pos = 0
	s.posBegin = 0
}

// duplex: the duplex call
/*
  We currently do not return anything (no number of bytes processed,
  no errors). TODO: think deeply about this :)
*/
func (s *Strobe) duplex(data []byte, cbefore, cafter, forceF bool) {

	// loop until all data has been processed
	for len(data) > 0 {

		if len(s.buf) == 0 && len(data) >= strobe_R {
			/*
			   This is the fast path; absorb a full "rate" bytes of input
			   and apply the permutation.
			*/
			if cbefore {
				var b [strobe_R]byte
				outState(s.a, b[:])
				for idx := 0; idx < strobe_R; idx++ {
					data[idx] ^= b[idx]
				}
			}

			xorState(&s.a, data[:strobe_R])

			if cafter {
				var b [strobe_R]byte
				outState(s.a, b[:])
				for idx := 0; idx < strobe_R; idx++ {
					data[idx] = b[idx]
				}
			}

			// what's next for the loop
			data = data[strobe_R:]

			// we filled the buffer -> apply padding + permutation
			s.runF()

		} else {
			/*
			   This is the slow path; buffer the input until we can fill
			   the sponge, and then xor it in.
			*/

			// how much can we fill?
			todo := strobe_R - len(s.buf)
			if todo > len(data) { // is it too much?
				todo = len(data)
			}

			if cbefore {
				var b [strobe_R]byte
				outState(s.a, b[:])
				for idx, state := range b[len(s.buf) : len(s.buf)+todo] {
					data[idx] ^= state
				}
			}

			s.buf = append(s.buf, data[:todo]...)

			if cafter {
				var b [strobe_R]byte
				outState(s.a, b[:])
				for idx, state := range b[len(s.buf)-todo : len(s.buf)] {
					data[idx] ^= state // because we actually didn't XOR yet
				}
			}

			// what's next for the loop?
			data = data[todo:]

			// If the sponge is full, time to XOR + padd + permutate.
			if len(s.buf) == strobe_R {
				xorState(&s.a, s.buf)
				s.runF()
			}
		}
	}

	// sometimes we the next operation to start on a new block
	if forceF && len(s.buf) != 0 {

		// zeros
		zerosStart := len(s.buf)
		s.buf = s.storage[:strobe_rate]
		for i := zerosStart; i < strobe_rate; i++ {
			s.buf[i] = 0
		}

		// xor
		xorState(&s.a, s.buf)
		// and pad+permute!
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
func (s *Strobe) operate(meta bool, operation string, data_ []byte, length int, more bool) []byte {

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
		flags.add("M")
	}

	// does the operation requires a length?
	var data []byte

	if operation == "PRF" || operation == "send_MAC" || operation == "RATCHET" {
		if length == 0 {
			panic("A length should be set for this operation.")
		}

		// create an empty data slice of the relevant size
		data = bytes.Repeat([]byte{0}, length)

	} else {
		if length != 0 {
			panic("Output length must be zero except for PRF, send_MAC and RATCHET operations.")
		}

		// copy the data not to modify the original data
		data = make([]byte, len(data_))
		copy(data, data_)
	}

	// Streaming more of the same operation?
	if more {
		if flags != s.cur_flags {
			panic("Flag should be the same when streaming operations.")
		}
	} else {
		// start the operation
		s.beginOp(flags)
		// remember operation in case of streaming (via `more`)
		s.cur_flags = flags
	}

	//
	// Init
	//

	/*
	   - both `cbefore` and `cafter` imply modification of the data
	   - `forceF` forces a permutation to allow following operations
	     to start on a new block
	*/

	cbefore := false
	cafter := false
	forceF := false

	//
	// Operations pre-duplex
	//

	if operation == "AD" { // A
		// nothing happens
	} else if operation == "KEY" { // AC
		cbefore = true
		forceF = true
	} else if operation == "PRF" { // IAC
		cbefore = true
		forceF = true
	} else if operation == "send_CLR" { // AT
		// nothing happens
	} else if operation == "recv_CLR" { // IAT
		// nothing happens
	} else if operation == "send_ENC" { // ACT
		cafter = true
		forceF = true
	} else if operation == "recv_ENC" { // IACT
		cbefore = true
		forceF = true
	} else if operation == "send_MAC" { // CT
		cafter = true
		forceF = true
	} else if operation == "recv_MAC" { // ICT
		cbefore = true
		forceF = true
	} else if operation == "RATCHET" { // C
		cbefore = true
		forceF = true
	} else {
		panic("operation not recognized")
	}

	//
	// Apply the duplex call
	//

	s.duplex(data, cbefore, cafter, forceF)

	//
	// Operation post-duplex
	//

	if operation == "AD" { // A
		// no output
	} else if operation == "KEY" { // AC
		// no output
	} else if operation == "PRF" { // IAC
		return data
	} else if operation == "send_CLR" { // AT
		return data
	} else if operation == "recv_CLR" { // IAT
		return data
	} else if operation == "send_ENC" { // ACT
		return data
	} else if operation == "recv_ENC" { // IACT
		return data
	} else if operation == "send_MAC" { // CT
		return data
	} else if operation == "recv_MAC" { // ICT
		// check MAC (constant-time)
		if more {
			panic("shouldn't be more")
		}
		var failures byte
		for _, data_byte := range data {
			failures |= data_byte
		}
		return []byte{failures} // 0 if correct, 1 if not
	} else if operation == "RATCHET" { // C
		// no output
	} else {
		panic("operation not recognized")
	}

	//
	return nil
}

// beginOp: starts an operation
func (s *Strobe) beginOp(flags flag) {

	// adjust direction information so that sender and receiver agree
	if flags.contains("T") {
		// no direction yet?
		if s.I0 == i_none {
			if flags.contains("I") {
				s.I0 = i_responder
			} else {
				s.I0 = i_initiator
			}
		}
		// if we're the initiator, toggle the I flag.
		if s.I0 == i_responder {
			flags.toggle("I")
		}
	}

	// start with oldBegin, then the new operation
	oldBegin := s.posBegin
	s.posBegin = uint8(len(s.buf) + 1) // s.pos + 1

	forceF := flags.contains("C") || flags.contains("K")

	// add the information to the state (and maybe permute)
	s.duplex([]byte{oldBegin, byte(flags)}, false, false, forceF)
}
