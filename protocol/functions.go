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

package protocol

import (
	"code.google.com/p/goprotobuf/proto"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/agl/ed25519"
)

const MAX_VALIDITY_PERIOD = 60 * 60 * 24 * 365 // seconds

func (pk Profile_PublicKey) ID() uint64 {
	return binary.LittleEndian.Uint64(sha256.New().Sum(pk.Ed25519)[:8])
}

var ErrSignatureVerificationFailed = errors.New("Signature verification failed")

func (pk Profile_PublicKey) VerifySignature(tag string, msg, sig []byte) error {
	if pk.Ed25519 == nil {
		return ErrSignatureVerificationFailed
	}
	smsg := append([]byte(tag+"\x00"), msg...)
	var pk_ed [ed25519.PublicKeySize]byte
	copy(pk_ed[:], pk.Ed25519)
	var sig_ed [ed25519.SignatureSize]byte
	copy(sig_ed[:], sig)
	if ed25519.Verify(&pk_ed, smsg, &sig_ed) {
		return nil
	} else {
		return ErrSignatureVerificationFailed
	}
}

func PBEncode(msg proto.Message) []byte {
	msgdata, err := proto.Marshal(msg)
	if err != nil {
		panic(err)
	}
	return msgdata
}

func Pad(msg []byte, l int) []byte {
	msg = append(msg, 1)
	if l > len(msg) {
		msg = append(msg, make([]byte, l-len(msg))...)
	}
	return msg
}

func Unpad(msg []byte) []byte {
	for len(msg) > 1 && msg[len(msg)-1] == 0 {
		msg = msg[:len(msg)-1]
	}
	if len(msg) > 0 {
		msg = msg[:len(msg)-1]
	}
	return msg
}

func Frame(msg []byte) []byte {
	buf := make([]byte, binary.MaxVarintLen64+len(msg))
	n := binary.PutUvarint(buf, uint64(len(msg)))
	copy(buf[n:], msg)
	return buf[:n+len(msg)]
}
