package sha3

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

import(
	"encoding/binary"
	"fmt"
	"bytes"
)

//
// Debug
// 

var Verbose bool

//
// Not so necessary High level APIs
// 

func (s *strobe) KEY(meta bool, key []byte) {
	s.Operate(meta, "KEY", key, 0, false)
}

func (s *strobe) PRF(meta bool, output_len int) []byte {
	return s.Operate(meta, "PRF", []byte{}, output_len, false)
}

func (s *strobe) send_ENC(meta bool, plaintext []byte) []byte {
	return s.Operate(meta, "send_ENC", plaintext, 0, false)
}

func (s *strobe) recv_ENC(meta bool, ciphertext []byte) []byte {
	return s.Operate(meta, "recv_ENC", ciphertext, 0, false)
}

func (s *strobe) AD(meta bool, additionalData []byte) {
	s.Operate(meta, "AD", additionalData, 0, false)
}

func (s *strobe) send_CLR(meta bool, cleartext []byte) {
	s.Operate(meta, "send_CLR", cleartext, 0, false)
}

func (s *strobe) recv_CLR(meta bool, cleartext []byte) {
	s.Operate(meta, "recv_CLR", cleartext, 0, false)
}

func (s *strobe) send_MAC(meta bool, output_length int) []byte {
	return s.Operate(meta, "send_MAC", []byte{}, output_length, false)
}

func (s *strobe) recv_MAC(meta bool, MAC []byte) bool {
	if s.Operate(meta, "recv_MAC", MAC, 0, false)[0] == 0 {
		return true
	}
	return false
}

func (s *strobe) RATCHET(meta bool, length int) {
	s.Operate(meta, "RATCHET", []byte{}, length, false)
}

//
// Defining STROBE's security
//

const(
	strobe_b    = 1600 // rate+capacity of the permutation
  strobe_N    = 200  // b/8 (rate+capacity in bytes)
	strobe_sec  = 256  // 256-bit of security
	strobe_rate = 136
	strobe_R    = 134  // N - (2*sec)/8 - 2
/*
  R (the block size) is the rate minus the strobe padding (1 byte) and 
  the cSHAKE padding (1 byte)
*/
)

//
// Strobe Objects
// 

type role uint8 // for strobe.I0

const(
	i_none      role = 2 // starting value
	i_initiator role = 0 // set if we send the first transport message
	i_responder role = 1 // set if we receive the first transport message 
)

/*
  We do not use strobe's `pos` variable here since it is easily 
  obtainable via `len(buf)`
*/
type strobe struct{
	// strobe specific
	initialized bool  // used to avoid padding during the first permutation
	pos_begin   uint8 // start of the current operation (0 := previous block)
	I0          role

	// streaming API
	cur_flags     flag

	// duplex construction (see sha3.go)
	a           [25]uint64
	buf         []byte
	rate        int
	storage     [strobe_rate]byte
}

//
// Flags
//

type flag uint8

var flagMap = map[rune]uint8{'A':1, 'C':2, 'T':3, 'M':4, 'K':5}

func createFlag(letters string) (flag flag) {
	flag.addFlags(letters)
	return
}

func (f *flag) addFlags(letters string) {
	for _, letter := range letters {
		offset, ok := flagMap[letter]; if ok {
			*f ^= 1 << offset
		}
	}
}

func (f *flag) getFlags() (flags string) {
	for letter, offset := range flagMap {
		if *f | (1 << offset) == *f {
			flags += string(letter)
		}
	}
	return flags
}

func (f *flag) contains(letters string) bool {
	for _, letter := range letters {
		if offset := flagMap[letter]; *f & (1 << offset) != *f {
			return false
		}
	}
	return true
}

func (f *flag) removeFlags(letters string) {
	for _, letter := range letters {
		if offset := flagMap[letter]; *f & (1 << offset) == *f {
			*f ^= 1 << offset
		}
	}
}

func (f *flag) toggleFlags(letters string) {
	for _, letter := range letters {
		*f ^= 1 << flagMap[letter]
	}
}

func (f *flag) resetFlags() {
	*f = 0
}

var OperationMap map[string]flag

func init() {
	OperationMap = map[string]flag{
		"AD": createFlag("A"),
		"KEY": createFlag("AC"),
		"PRF": createFlag("IAC"),
		"send_CLR": createFlag("AT"),
		"recv_CLR": createFlag("IAT"),
		"send_ENC": createFlag("ACT"),
		"recv_ENC": createFlag("IACT"),
		"send_MAC": createFlag("CT"),
		"recv_MAC": createFlag("ICT"),
		"RATCHET": createFlag("C"),
	}
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
func InitStrobe(customization_string string) (s strobe) {

  /*
  // Go already set these values to zero
	s.pos_begin = 0
	s.cur_flags = 0
  */
	s.I0 = i_none
	s.initialized = false
	domain := []byte{1, strobe_R, 1, 0, 1, 12*8}
	domain = append(domain, []byte("STROBEv1.0.2")...)

	// init duplex construction
	s.buf = s.storage[:0]

	// run the permutation
	s._duplex(domain, false, false, true)
	s.initialized = true

	// run the customization string in META mode
	s.Operate(true, "AD", []byte(customization_string), 0, false)

	//
	return
}

// _runF: applies the STROBE's + cSHAKE's padding and the Keccak permutation
func (s *strobe) _runF() {
  /*
    we do not run this padding during Strobe's initialization.
    This allow us to respect cSHAKE's specification.
  */
	if s.initialized{
		// STROBE's padding
		s.buf = append(s.buf, s.pos_begin)
		// cSHAKE's padding
		s.buf = append(s.buf, 0x04)
		// zeros
		zerosStart := len(s.buf)
		s.buf = s.storage[:strobe_rate]   
		for i := zerosStart; i < strobe_rate; i++ {
			s.buf[i] = 0
		}
		// final bit
		s.buf[strobe_rate - 1] ^= 0x80
	}

	// permutation
	keccakF1600(&s.a)

	// init new block
	s.buf = s.storage[:0]	//	s.pos = 0
	s.pos_begin = 0
}


// _duplex: the duplex call
/*
  We currently do not return anything (no number of bytes processed, 
  no errors). TODO: think deeply about this :)
*/
func (s *strobe) _duplex(data []byte, cbefore, cafter, forceF bool) {

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
			s._runF()

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
				for idx, state := range b[len(s.buf):len(s.buf) + todo] {
					data[idx] ^= state
				}
			}

			s.buf = append(s.buf, data[:todo]...)

			if cafter {
				var b [strobe_R]byte
				outState(s.a, b[:])
				for idx, state := range b[len(s.buf) - todo:len(s.buf)] {
					data[idx] ^= state // because we actually didn't XOR yet
				}
			}

			// what's next for the loop?
			data = data[todo:]
			
			// If the sponge is full, time to XOR + padd + permutate.
			if len(s.buf) == strobe_R {
				xorState(&s.a, s.buf)
				s._runF()
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
		s._runF()
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
func (s *strobe) Operate(meta bool, operation string, data_ []byte, length int, more bool) (data []byte) {

	//
	// Operation checks
	//
	
	// operation is valid?
	var flags flag
	var ok bool
	if flags, ok = OperationMap[operation]; !ok {
		panic("not a valid operation")
	}

	// operation is meta?
	if meta {
		flags.addFlags("M")
	}

	// does the operation requires a length?
	if operation == "PRF" || operation != "send_MAC" || operation != "RATCHET" {
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
		s._beginOp(flags)
		// remember operation in case of streaming (via `more`)
		s.cur_flags	 = flags
	}

	//
	// Init
	//

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

	s._duplex(data, cbefore, cafter, forceF)

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
			panic ("shouldn't be more")
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

// _beginOp: starts an operation
func (s *strobe) _beginOp(flags flag) {

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
			flags.toggleFlags("I")
		}
	}

	// start with old_begin, then the new operation 
	old_begin := s.pos_begin
	s.pos_begin = uint8(len(s.buf) + 1) // s.pos + 1

	forceF := flags.contains("C") || flags.contains("K")

	// add the information to the state (and maybe permute)
	s._duplex([]byte{old_begin, byte(flags)}, false, false, forceF)
}
