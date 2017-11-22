# StrobeGo

This repository contains an implementation of the [Strobe protocol framework](https://strobe.sourceforge.io/).

**The implementation of Strobe has not been thoroughly tested. Do not use this in production**.

The **Strobe** implementation is heavily based on [golang.org/x/crypto/sha3](https://godoc.org/golang.org/x/crypto/sha3), which is why some of the files have been copied in the [/strobe](/strobe) directory. You do not need to have Go's SHA-3 package to make it work.

The **cSHAKE** implementation is intended to be dropped in the Go's SHA-3 package. See [the instructions below](#cshake-install) for more information.

## Install

To use it, first get Go's experimental sha3's implementation:

```
go get github.com/mimoo/StrobeGo/strobe
```

## Usage

In your go file:

```go
import "github.com/mimoo/StrobeGo/strobe"
```

