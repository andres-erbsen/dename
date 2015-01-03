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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/agl/ed25519"
	. "github.com/andres-erbsen/dename/client"
	. "github.com/andres-erbsen/dename/protocol"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"
)

var invite_key []byte

func create_invite_token() []byte {
	nonce := make([]byte, 8)
	_, err := rand.Read(nonce)
	if err != nil {
		panic(err)
	}
	mac := hmac.New(sha256.New, invite_key)
	mac.Write(nonce[:])
	return append(nonce, mac.Sum(nil)[:8]...)
}

var client *Client
var sk *[ed25519.PrivateKeySize]byte
var profile *Profile

func register(name string) {
	for {
		err := client.Register(sk, name, profile, create_invite_token())
		if err != nil {
			log.Print(name, err)
			if err == ErrNotAuthorized {
				break
			}
			continue
		}
		return
	}
}

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("Usage: %s <invitekey> <num_regs> <parallelism>", os.Args[0])
	}
	var err error
	invite_key, err = ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	var nr_requests, parallelism int
	fmt.Sscan(os.Args[2], &nr_requests)
	fmt.Sscan(os.Args[3], &parallelism)

	profile, sk, err = NewProfile(nil, nil)
	if err != nil {
		log.Fatalf("Could not create profile: %v", err)
	}

	cfg := new(Config)
	if err := gcfg.ReadFileInto(cfg, "dnmclient.cfg"); err != nil {
		log.Fatalf("Failed to load config from dnmclient.cfg: %v", err)
	}
	client, err = NewClient(cfg, nil, nil)
	if err != nil {
		log.Fatalf("Could not create client: %v", err)
	}

	start_time := time.Now()

	connection_slots := make(chan struct{}, parallelism)
	var wg sync.WaitGroup
	wg.Add(nr_requests)
	for i := 0; i < nr_requests; i++ {
		connection_slots <- struct{}{}
		go func(i int) {
			register(fmt.Sprintf("%d %d", start_time.UnixNano(), i))
			<-connection_slots
			fmt.Printf("%d done", i)
			wg.Done()
		}(i)
	}
	wg.Wait()
	time_taken := time.Now().Sub(start_time)
	fmt.Printf("Took %s: %f rq/s\n", time_taken.String(), float64(nr_requests)/time_taken.Seconds())
}
