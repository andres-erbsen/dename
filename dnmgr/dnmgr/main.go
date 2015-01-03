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
	"encoding/base64"
	"fmt"
	"github.com/andres-erbsen/dename/client"
	"github.com/andres-erbsen/dename/dnmgr"
	"io/ioutil"
	"os"
)

func usageAndExit() {
	fmt.Fprintf(os.Stderr, `Missing arguments. Usage:
To create a new profile:
  %s init <name> <invite>
To set the value of a field on an existing profile:
  %s set <name> <field> [value]
If a value is not provided in the arguments, it will be read from standard input.
This is(useful if the value contains nul characters.
`, os.Args[0], os.Args[0])
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usageAndExit()
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "init":
		if len(args) < 2 {
			usageAndExit()
		}
		name := []byte(args[0])
		invite, err := base64.StdEncoding.DecodeString(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid invite (base64 decoding failed: %s)\n", err)
			os.Exit(1)
		}
		profile, sk, err := client.NewProfile(nil, nil)
		if err != nil {
			panic(err)
		}
		if err := dnmgr.Register(sk, profile, name, invite, "", nil); err != nil {
			fmt.Fprintf(os.Stderr, "registration failed: %s\n", err)
			os.Exit(1)
		}
	case "set":
		var name, fieldName string
		var value []byte
		if len(args) == 2 || len(args) == 3 {
			name, fieldName = args[0], args[1]
			if len(args) == 3 {
				value = []byte(args[3])
			}
		} else {
			usageAndExit()
		}
		if value == nil {
			var err error
			value, err = ioutil.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
				os.Exit(1)
			}
		}
		fieldNumber, err := client.FieldByName(fieldName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unknown field \"%s\" (%s)\n", fieldName, err)
			os.Exit(1)
		}
		if err := dnmgr.SetProfileField([]byte(name), fieldNumber, value, "", nil); err != nil {
			fmt.Fprintf(os.Stderr, "operation failed: %s\n", err)
			os.Exit(1)
		}
	}
}
