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
	. "github.com/andres-erbsen/dename/protocol"
	"fmt"
	"testing"
)

func TestCollectConsistentGetsAll(t *testing.T) {
	const (
		n = 5
	)
	c := &communicator{
		servers:       make(map[uint64]*ServerInfo),
		recallMessage: func(uint64, uint64, uint64) *SignedServerMessage { return nil },
	}
	for i := 0; i < n; i++ {
		mb := new(MessageBroker)
		c.servers[uint64(i)] = &ServerInfo{ID: uint64(i), messageBroker: mb, IsCore: true}
	}
	for i := 0; i < n; i++ {
		one := uint64(1)
		from := uint64(i)
		msg := new(Message)
		msg.Round = &one
		msg.Server = &from
		msg.HashOfOperations = []byte{0xff}
		c.servers[uint64(i)].messageBroker.OnReceive(msg)
	}
	ms, err := c.CollectGloballyConsistent(
		1, 1,
		func(m *Message) string { return fmt.Sprintf("%x", m.HashOfOperations) },
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != n {
		t.Fatalf("Wrong count; %d not %d", len(ms), n)
	}
}
