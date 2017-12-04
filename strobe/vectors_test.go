package strobe

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

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
	outputData := s.Operate(meta, operation, inputData, inputLength, stream)
	if len(outputData) > 0 {
		op.OpOutput = hex.EncodeToString(outputData)
	}
	// state
	op.OpStateAfter = s.debugPrintState()
	//
	return
}

type TestVector struct {
	Name       string      `json:"name"`
	Operations []Operation `json:"operations"`
}

type TestVectors struct {
	TestVectors []TestVector `json:"test_vectors"`
}

func TestGenTestVectors(t *testing.T) {
	// skipping this
	//	if testing.Short() {
	t.Skip("skipping generation of test vectors.")
	//	}

	// test vector file
	out, err := os.Create("test_vectors/test_vectors.json")
	if err != nil {
		t.Fatal("couldn't create test vector file")
	}
	defer out.Close()

	// the structure
	var testVectors TestVectors

	// start the run
	testVector := TestVector{Name: "run1"}

	// init
	s, op := DebugInit("custom string", 128)
	testVector.Operations = append(testVector.Operations, op)

	// KEY
	key := []byte("010101")
	testVector.Operations = append(testVector.Operations, s.DebugGoThroughOperation("KEY", false, key, 0, false))
	// AD
	message := []byte("hello, how are you good sir?")
	testVector.Operations = append(testVector.Operations, s.DebugGoThroughOperation("AD", true, message, 0, false))
	// PRF
	testVector.Operations = append(testVector.Operations, s.DebugGoThroughOperation("PRF", false, []byte{}, 16, false))

	// save the run
	testVectors.TestVectors = append(testVectors.TestVectors, testVector)

	// output

	jsonOutput, _ := json.Marshal(testVectors)
	fmt.Fprintf(out, string(jsonOutput))
}
