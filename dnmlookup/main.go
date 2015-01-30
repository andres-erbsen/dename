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
	"code.google.com/p/gcfg"
	"fmt"
	"github.com/andres-erbsen/dename/client"
	"github.com/andres-erbsen/dename/protocol"
	"os"
	"path/filepath"
)


func usageAndExit(str string) {
	if str != "" {
		fmt.Fprintf(os.Stderr, "%s\n", str)
	}
	fmt.Fprintf(os.Stderr, "usage:" +
		"\t%s <name> [field] # get the value for a field.\n" +
		"\t\t                   Possible fields are: bitcoin, dename, dename-transport, dns,\n" +
		"\t\t                   email, gpg, http, jabber, openpgp, otr, pgp, ssh, ssh-host,\n" +
		"\t\t                   textsecure, tor, web, or xmpp\n",
		os.Args[0])

	os.Exit(1)
}

func main() {
	if !(2 <= len(os.Args) && len(os.Args) <= 3) {
		usageAndExit("")
	}
	name := os.Args[1]
	var field int32
	if len(os.Args) == 3 {
		var err error
		field, err = client.FieldByName(os.Args[2])
		if err != nil {
			usageAndExit("unknown field")
		}
	}

	clientCfg := new(client.Config)
	err := gcfg.ReadFileInto(clientCfg, filepath.Join(os.Getenv("HOME"), ".config", "dename", "authorities.cfg"))
	if os.IsNotExist(err) {
		clientCfg = nil
	} else if err != nil {
		panic(err)
	}
	dnmc, err := client.NewClient(clientCfg, nil, nil)
	if err != nil {
		panic(err)
	}
	profile, err := dnmc.Lookup(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lookup failed: %s\n", err)
		os.Exit(3)
	}

	if profile == nil {
		os.Exit(1)
	}

	var value []byte
	if field == 0 {
		value = protocol.PBEncode(profile)
	} else {
		if value, err = client.GetProfileField(profile, field); err != nil {
			// fmt.Fprintf(os.Stderr, "could not read field \"%s\": %s\n", os.Args[3], err)
			os.Exit(1)
		}
	}
	if _, err = os.Stdout.Write(value); err != nil {
		panic(err)
	}
}
