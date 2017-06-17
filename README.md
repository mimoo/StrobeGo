# StrobeGo

This repository contains some work on the [Strobe protocol framework](https://strobe.sourceforge.io/).

* [/strobe](/strobe) contains a readable implementation of Strobe.
* [/golang.org/x/crypto/sha3](/golang.org/x/crypto/sha3) contains an implementation of [cSHAKE](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf).

The implementation of Strobe has not been thoroughly tested, nor does it completely respect the specification. [See this blog post for more information](https://www.cryptologie.net/article/398/strobego/). It is here for experimentation purposes.

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

See [test_strobe.go](/test_strobe.go) on how to use the function.

## cSHAKE Install

Get it via

```sh
go get golang.org/x/crypto/sha3
```

then move the file in the SHA-3 directory:

```sh
cp StrobeGo/golang.org/x/crypto/sha3/*.go $GOPATH/src/golang.org/x/crypto/sha3/
```
