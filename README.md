# StrobeGo

[![GoDoc](https://godoc.org/github.com/mimoo/StrobeGo?status.svg)](https://godoc.org/github.com/mimoo/StrobeGo)

This repository contains an implementation of the [Strobe protocol framework](https://strobe.sourceforge.io/). See [this blogpost](https://www.cryptologie.net/article/416/the-strobe-protocol-framework/) for an explanation of what is the framework.

**The implementation of Strobe has not been thoroughly tested. Do not use this in production**.

The **Strobe** implementation is heavily based on [golang.org/x/crypto/sha3](https://godoc.org/golang.org/x/crypto/sha3), which is why some of the files have been copied in the [/strobe](/strobe) directory. You do not need to have Go's SHA-3 package to make it work.

The **cSHAKE** implementation is intended to be dropped in the Go's SHA-3 package. See [the instructions below](#cshake-install) for more information.

## Install

To use it, first get Go's experimental sha3's implementation:

```
go get github.com/mimoo/StrobeGo/strobe
```

## Usage

See [godoc](https://godoc.org/github.com/mimoo/StrobeGo/strobe) for thorough documentation. Here is an example usage:

```go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/mimoo/StrobeGo/strobe"
)

func main() {
	fmt.Println("=======InitStrobe(\"hello\", 128)========")
	s := strobe.InitStrobe("hello", 128)
	fmt.Println("=======s.PRF(16)========")
	fmt.Println(hex.EncodeToString(s.PRF(16)))
	fmt.Println("=======s.send_CLR(false, \"hi\")========")
	s.Send_CLR(false, []byte("hi"))
	fmt.Println("=======s.send_ENC(false, \"hello\")========")
	fmt.Println(hex.EncodeToString(s.Send_ENC_unauthenticated(false, []byte("hello"))))
		fmt.Println("=======s.send_MAC(true, 16)========")
	fmt.Println(hex.EncodeToString(s.Send_MAC(true, 16)))
}
