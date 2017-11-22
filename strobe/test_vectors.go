package strobe

import "encoding/hex"

// Operation is holding a test vector operation
type Operation struct {
	OpName        string `json:"name"`
	OpMeta        bool   `json:"meta,omitempty"`
	OpInputData   string `json:"input_data,omitempty"`
	OpInputLength int    `json:"input_length,omitempty"`
	OpOutput      string `json:"output,omitempty"`
	OpStateAfter  string `json:"state_after"`
	OpStream      bool   `json:"stream,omitempty"`
}

func DebugInit(customString string, security int) (_ Strobe, op Operation) {

	s := InitStrobe(customString, security)

	op.OpName = "init"
	op.OpInputData = customString
	op.OpInputLength = 128
	op.OpStateAfter = s.debugPrintState()

	//
	return s, op
}

func (s *Strobe) DebugGoThroughOperation(operation string, meta bool, inputData []byte, inputLength int, stream bool) (op Operation) {
	// create operation object
	op.OpName = operation
	op.OpInputData = hex.EncodeToString(inputData)
	op.OpInputLength = inputLength
	op.OpMeta = meta
	op.OpStream = stream
	// go through operation
	outputData := s.operate(meta, operation, inputData, inputLength, stream)
	if len(outputData) > 0 {
		op.OpOutput = hex.EncodeToString(outputData)
	}
	// state
	op.OpStateAfter = s.debugPrintState()
	//
	return
}
