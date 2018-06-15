// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"github.com/agl/ed25519"
	"github.com/agl/ed25519/edwards25519"
	"fmt"
)

func main()  {
	TestSignVerify()
}

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 0
	}
	return len(buf), nil
}

func TestUnmarshalMarshal() {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	var A edwards25519.ExtendedGroupElement
	if !A.FromBytes(pub) {
		fmt.Println("ExtendedGroupElement.FromBytes failed")
	}

	var pub2 [32]byte
	A.ToBytes(&pub2)

	if *pub != pub2 {
		fmt.Printf("FromBytes(%v)->ToBytes does not round-trip, got %x\n", *pub, pub2)
	}
}

func TestSignVerify() {
	var zero zeroReader
	public, private, _ := ed25519.GenerateKey(zero)
	fmt.Println(public)
	fmt.Println(string((*public)[:]))
	fmt.Println(private)
	fmt.Println(string((*private)[:]))

	message := []byte("test message")
	sig := ed25519.Sign(private, message)
	if !ed25519.Verify(public, message, sig) {
		fmt.Printf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if ed25519.Verify(public, wrongMessage, sig) {
		fmt.Printf("signature of different message accepted")
	}
}

func TestGolden() {
	// sign.input.gz is a selection of test cases from
	// http://ed25519.cr.yp.to/python/sign.input
	testDataZ, err := os.Open("sign.input.gz")
	if err != nil {
		fmt.Println(err)
	}
	defer testDataZ.Close()
	testData, err := gzip.NewReader(testDataZ)
	if err != nil {
		fmt.Println(err)
	}
	defer testData.Close()

	in := bufio.NewReaderSize(testData, 1<<12)
	lineNo := 0
	for {
		lineNo++
		lineBytes, isPrefix, err := in.ReadLine()
		if isPrefix {
			fmt.Println("bufio buffer too small")
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("error reading test data: %s", err)
		}

		line := string(lineBytes)
		parts := strings.Split(line, ":")
		if len(parts) != 5 {
			fmt.Println("bad number of parts on line %d", lineNo)
		}

		privBytes, _ := hex.DecodeString(parts[0])
		pubKeyBytes, _ := hex.DecodeString(parts[1])
		msg, _ := hex.DecodeString(parts[2])
		sig, _ := hex.DecodeString(parts[3])
		// The signatures in the test vectors also include the message
		// at the end, but we just want R and S.
		sig = sig[:ed25519.SignatureSize]

		if l := len(pubKeyBytes); l != ed25519.PublicKeySize {
			fmt.Println("bad public key length on line %d: got %d bytes", lineNo, l)
		}

		var priv [ed25519.PrivateKeySize]byte
		copy(priv[:], privBytes)
		copy(priv[32:], pubKeyBytes)

		sig2 := ed25519.Sign(&priv, msg)
		if !bytes.Equal(sig, sig2[:]) {
			fmt.Println("different signature result on line %d: %x vs %x", lineNo, sig, sig2)
		}

		var pubKey [ed25519.PublicKeySize]byte
		copy(pubKey[:], pubKeyBytes)
		if !ed25519.Verify(&pubKey, msg, sig2) {
			fmt.Println("signature failed to verify on line %d", lineNo)
		}
	}
}

/*func BenchmarkKeyGeneration(b *testing.B) {
	var zero zeroReader
	for i := 0; i < b.N; i++ {
		if _, _, err := ed25519.GenerateKey(zero); err != nil {
			fmt.Println(err)
		}
	}
}*/

/*func BenchmarkSigning(b *testing.B) {
	var zero zeroReader
	_, priv, err := ed25519.GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Sign(priv, message)
	}
}*/

/*
func BenchmarkVerification(b *testing.B) {
	var zero zeroReader
	pub, priv, err := ed25519.GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature := ed25519.Sign(priv, message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Verify(pub, message, signature)
	}
}*/
