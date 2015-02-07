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
	"github.com/agl/ed25519"
	. "github.com/andres-erbsen/dename/protocol"
	"io/ioutil"
	"log"
	"fmt"
	"path"
	"os"
)

const SECRET_KEY string = "secret_key"
const PUBLIC_KEY string = "public_key"

func main() {
	var dir string

	if len(os.Args) < 2 {
		dir = "."
	} else {
		dir = os.Args[1]
	}

	skfile := path.Join(dir, SECRET_KEY)
	pkfile := path.Join(dir, PUBLIC_KEY)

	if _, err := os.Stat(skfile); err == nil {
		fmt.Fprintf(os.Stderr, "%s already exists\n", skfile)
		os.Exit(1)
	}
	if _, err := os.Stat(pkfile); err == nil {
		fmt.Fprintf(os.Stderr, "%s already exists\n", pkfile)
		os.Exit(1)
	}

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	if err := ioutil.WriteFile(skfile, sk[:], 0600); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	data := PBEncode(&Profile_PublicKey{Ed25519: pk[:]})
	if err := ioutil.WriteFile(pkfile, data, 0644); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
