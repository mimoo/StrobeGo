# StrobeGo

This is readable implementation of [STROBE](https://strobe.sourceforge.io/) in Go.

It has not been thoroughlytested, nor does it completely respect the specification. [See this blog post for more information](https://www.cryptologie.net/article/398/strobego/).

Note: This repository also includes an implementation of [cSHAKE](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf).

## Install

To use it, first get Go's experimental sha3's implementation:

```
go get golang.org/x/crypto/sha3
```

Then copy the files into this package

```
git clone git@github.com:mimoo/StrobeGo.git 
cp StrobeGo/golang.org/x/crypto/sha3/*.go $GOPATH/src/golang.org/x/crypto/sha3/
```

## Usage

See `test_strobe.go` on how to use the function.


