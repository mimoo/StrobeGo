# StrobeGo

This repository contains some work on the [STROBE protocol framework](https://strobe.sourceforge.io/).

* [/strobe](/strobe) contains a readable implementation of Strobe.
* [/golang.org/x/crypto/sha3](/golang.org/x/crypto/sha3) contains an implementation of [cSHAKE](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf).

The implementation of Strobe has not been thoroughly tested, nor does it completely respect the specification. [See this blog post for more information](https://www.cryptologie.net/article/398/strobego/). It is here for experimentation purposes.

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
