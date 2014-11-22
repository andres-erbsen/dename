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

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

var INVITE_KEY = []byte("very secret text in the source")

func mktoken() []byte {
	var r [8]byte
	rand.Read(r[:])
	mac := hmac.New(sha256.New, INVITE_KEY)
	mac.Write(r[:])
	return append(r[:], mac.Sum(nil)[:8]...)
}

func newSerial() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}
	return serialNumber
}

var testing_ca_priv *ecdsa.PrivateKey
var testing_ca_cert *x509.Certificate
var testing_ca_pool *x509.CertPool
var testing_tls_config *tls.Config

func init() {
	var err error
	testing_ca_priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		panic(err)
	}
	testing_ca_cert = &x509.Certificate{
		Subject:               pkix.Name{CommonName: "testingCA"},
		SerialNumber:          newSerial(),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(100000 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:       true,
		MaxPathLen: 4,
	}
	testingCAder, err := x509.CreateCertificate(rand.Reader, testing_ca_cert, testing_ca_cert, &testing_ca_priv.PublicKey, testing_ca_priv)
	if err != nil {
		panic(err)
	}
	testing_ca_cert, err = x509.ParseCertificate(testingCAder)
	if err != nil {
		panic(err)
	}
	testing_ca_pool = x509.NewCertPool()
	testing_ca_pool.AddCert(testing_ca_cert)
	testing_tls_config = &tls.Config{RootCAs: testing_ca_pool}
}

func putCert(certfile, keyfile string) {
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		panic(err)
	}
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "testingServer"},
		SerialNumber: newSerial(),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(100000 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, testing_ca_cert, &priv.PublicKey, testing_ca_priv)
	if err != nil {
		panic(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	certOut, err := os.Create(certfile)
	if err != nil {
		panic(err)
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err != nil {
		panic(err)
	}
	certOut.Close()
	keyOut, err := os.OpenFile(keyfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "127.0.0.1", Roots: testing_ca_pool}); err != nil {
		panic(err)
	}
	skBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		panic(err)
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: skBytes})
	if err != nil {
		panic(err)
	}
	keyOut.Close()
}
