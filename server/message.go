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
	"code.google.com/p/goprotobuf/proto"
	. "github.com/andres-erbsen/dename/protocol"
)

const (
	PHASE_HASH_OPS = 1 + iota
	PHASE_HASH_HASHES
	PHASE_OPS
	PHASE_HASH_STATE
)

var true_, false_ = true, false // cannot take address of constant...

type Message struct {
	SignedServerMessage_ServerMessage
	SignedServerMessage *SignedServerMessage
}

func (msg *Message) Phase() int {
	if msg.HashOfOperations != nil {
		return PHASE_HASH_OPS
	} else if msg.HashOfHashes != nil {
		return PHASE_HASH_HASHES
	} else if msg.Operations != nil {
		return PHASE_OPS
	} else if msg.HashOfState != nil {
		return PHASE_HASH_STATE
	} else {
		return -1
	}
}

func msgHashOfHashes_s(msg *Message) string {
	return string(msg.HashOfHashes)
}
func msgHashOfState_s(msg *Message) string {
	return string(msg.HashOfState)
}

func MustUnmarshal(encoded []byte, pb proto.Message) {
	if err := proto.Unmarshal(encoded, pb); err != nil {
		panic("unexpected invalid protobuf")
	}
}
