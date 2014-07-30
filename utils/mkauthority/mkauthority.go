// Copyright 2014 The Dename Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

func newSerial() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}
	return serialNumber
}

func main() {
	var err error
	ca_priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		panic(err)
	}
	ca_cert := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "testingCA"},
		SerialNumber:          newSerial(),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(100000 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:       true,
		MaxPathLen: 4,
	}
	ca_der, err := x509.CreateCertificate(rand.Reader, ca_cert, ca_cert, &ca_priv.PublicKey, ca_priv)
	if err != nil {
		panic(err)
	}
	ca_cert, err = x509.ParseCertificate(ca_der)
	if err != nil {
		panic(err)
	}
	err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: ca_der})
	if err != nil {
		panic(err)
	}
	sk_bytes, err := x509.MarshalECPrivateKey(ca_priv)
	if err != nil {
		panic(err)
	}
	err = pem.Encode(os.Stderr, &pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: sk_bytes})
	if err != nil {
		panic(err)
	}
}
