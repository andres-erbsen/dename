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
	"crypto/rand"
	. "github.com/andres-erbsen/dename/protocol"
	"github.com/agl/ed25519"
	"os"
)

func main() {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	if _, err := os.Stderr.Write(sk[:]); err != nil {
		panic(err)
	}
	if _, err := os.Stdout.Write(PBEncode(&Profile_PublicKey{Ed25519: pk[:]})); err != nil {
		panic(err)
	}
}
