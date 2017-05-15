# StrobeGo

This is readable implementation of [STROBE](https://strobe.sourceforge.io/) in Go.

To use it, first get Go's experimental sha3's implementation:

```
go get golang.org/x/crypto/sha3
```

Then copy the files into this package

```
git clone git@github.com:mimoo/StrobeGo.git 
cp StrobeGo/golang.org/x/crypto/sha3/*.go $GOPATH/src/golang.org/x/crypto/sha3/
```

See `test_strobe.go` on how to use the function.

Note: This repository also includes an implementation of [cSHAKE](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf).
