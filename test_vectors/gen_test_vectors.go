package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mimoo/StrobeGo/strobe"
)

type TestVector struct {
	Name       string             `json:"name"`
	Operations []strobe.Operation `json:"operations"`
}

type TestVectors struct {
	TestVectors []TestVector `json:"test_vectors"`
}

func main() {

	var testVectors TestVectors

	// start the run
	testVector := TestVector{Name: "run1"}

	// init
	s, op := strobe.DebugInit("custom string", 128)
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
	out := os.Stdout

	jsonOutput, _ := json.Marshal(testVectors)
	fmt.Fprintf(out, string(jsonOutput))
}
