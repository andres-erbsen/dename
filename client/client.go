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


package client

import (
	"bytes"
	"code.google.com/p/go.net/proxy"
	"code.google.com/p/goprotobuf/proto"
	_ "crypto/sha512" // for tls
	"crypto/tls"
	. "github.com/andres-erbsen/dename/protocol"
	"encoding/binary"
	"fmt"
	"github.com/agl/ed25519"
	"io"
	"net"
	"time"
)

var true_ = true
var pad_to uint64 = 4 << 10

type serverInfo struct {
	pk        *Profile_PublicKey
	address   string
	timeout   time.Duration
	tlsConfig *tls.Config
}

type Client struct {
	freshnessThreshold        time.Duration
	freshnessNumConfirmations int
	consensusNumConfirmations int
	dialer                    proxy.Dialer
	servers                   map[uint64]*serverInfo
}

func (c *Client) connect(s *serverInfo) (net.Conn, error) {
	var plainconn net.Conn
	plainconn, err := c.dialer.Dial("tcp", s.address)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(plainconn, s.tlsConfig)
	conn.SetDeadline(time.Now().Add(s.timeout))
	return conn, conn.Handshake()
}

func (c *Client) atSomeServer(f func(net.Conn) (bool, error)) (err error) {
next_server:
	for _, server := range c.servers {
		var conn net.Conn
		conn, err = c.connect(server)
		if err != nil {
			continue next_server
		}
		var done bool
		done, err = f(conn)
		if done {
			conn.Close()
			return err
		}
		conn.Close()
	}
	return err
}

// Lookup retrieves the profile that corresponds to name from any server in the
// client's config. It is guaranteed that at least NumConfirmations of the
// servers have confirmed the correctness of the (name, profile) mapping and
// that Freshness.NumConfirmations have done this within Freshness.Threshold.
func (c *Client) Lookup(name []byte) (profile *Profile, err error) {
	err = c.atSomeServer(func(conn net.Conn) (bool, error) {
		rq := &ClientMessage{PeekState: &true_, ResolveName: name, PadReplyTo: &pad_to}
		if _, err = conn.Write(Frame(Pad(PBEncode(rq), 256))); err != nil {
			return false, err
		}
		var reply *ClientReply
		if reply, err = readReply(conn); err != nil {
			return false, err
		}
		var root []byte
		root, err = c.VerifyConsensus(reply.StateConfirmations)
		if err != nil {
			return true, ErrCouldntVerify
		}
		profileBs, err := VerifyResolveAgainstRoot(root, name, reply.LookupNodes)
		if err != nil {
			return true, ErrCouldntVerify
		}
		if profileBs == nil {
			profile = nil
		} else {
			profile = new(Profile)
			err = proto.Unmarshal(profileBs, profile)
			if err != nil {
				return true, err
			}
		}
		return true, nil
	})
	return
}

var (
	ErrRegistrationDisabled = fmt.Errorf("registration disabled")
	ErrInviteInvalid        = fmt.Errorf("invite not valid")
	ErrInviteUsed           = fmt.Errorf("invite already used")
	ErrNotAuthorized        = fmt.Errorf("not authorized")
	ErrCouldntVerify        = fmt.Errorf("could not verify the correctness of the response")
)

// Enact is a low-level function that completes an already complete profile
// operation at any known server. You probably want to use Register, Modify or
// Transfer instead.
func (c *Client) Enact(op *SignedProfileOperation, invite []byte) (err error) {
	err = c.atSomeServer(func(conn net.Conn) (bool, error) {
		msg := &ClientMessage{ModifyProfile: op, InviteCode: invite}
		_, err = conn.Write(Frame(Pad(PBEncode(msg), 4<<10)))
		if err != nil {
			return false, err
		}
		var reply *ClientReply
		reply, err = readReply(conn)
		if err != nil {
			return false, err
		}
		switch reply.GetStatus() {
		case ClientReply_OK:
			return true, nil
		case ClientReply_REGISTRATION_DISABLED:
			return false, ErrRegistrationDisabled
		case ClientReply_INVITE_INVALID:
			return false, ErrInviteInvalid
		case ClientReply_INVITE_USED:
			return false, ErrInviteUsed
		case ClientReply_NOT_AUTHORIZED:
			return false, ErrNotAuthorized
		default:
			return false, fmt.Errorf("unknown status code")
		}
	})
	return
}

type byteReader struct{ io.Reader }

func (r byteReader) ReadByte() (byte, error) {
	var ret [1]byte
	_, err := io.ReadFull(r, ret[:])
	return ret[0], err
}

func readReply(conn net.Conn) (reply *ClientReply, err error) {
	var size uint64
	size, err = binary.ReadUvarint(byteReader{conn})
	if err != nil {
		return
	}
	if size > 5<<10 {
		return nil, fmt.Errorf("reply too big")
	}
	buf := make([]byte, size)
	if _, err = io.ReadFull(conn, buf); err != nil {
		return
	}
	reply = new(ClientReply)
	err = proto.Unmarshal(Unpad(buf), reply)
	return
}

// Low-level convenience function to create a SignedProfileOperation with no
// signatures. You probably want to use Register, Modify or Transfer instead.
func MakeOperation(name []byte, profile *Profile) *SignedProfileOperation {
	return &SignedProfileOperation{
		ProfileOperation: PBEncode(&SignedProfileOperation_ProfileOperationT{
			Name:       name,
			NewProfile: PBEncode(profile),
		}),
	}
}

// Creates a signed operation structure to transfer name to profile. To make
// this change take effect, the recipient has to call AcceptTransfer with the
// secret key whose public counterpart is in profile.
func TransferProposal(sk *[ed25519.PrivateKeySize]byte, name []byte,
	profile *Profile) *SignedProfileOperation {
	return OldSign(sk, MakeOperation(name, profile))
}

// Gives the old owner's signature for op using sk
func OldSign(sk *[ed25519.PrivateKeySize]byte, op *SignedProfileOperation) *SignedProfileOperation {
	msg := append([]byte("ModifyProfileOld\x00"), op.ProfileOperation...)
	op.OldProfileSignature = ed25519.Sign(sk, msg)[:]
	return op
}

// Gives the new owner's signature for op using sk
func NewSign(sk *[ed25519.PrivateKeySize]byte, op *SignedProfileOperation) *SignedProfileOperation {
	msg := append([]byte("ModifyProfileNew\x00"), op.ProfileOperation...)
	op.NewProfileSignature = ed25519.Sign(sk, msg)[:]
	return op
}

// Register associates a profile with a name. The invite is used to convince
// the server that we are indeed allowed a new name, it is not associated with
// the profile in any way. If profile.Version is set, it must be 0.
func (c *Client) Register(sk *[ed25519.PrivateKeySize]byte, name []byte, profile *Profile, invite []byte) error {
	return c.Enact(NewSign(sk, MakeOperation(name, profile)), invite)
}

// AcceptTransfer uses the new secret key and the transfer operation generated
// using the old secret key to associate the op.Name with op.NewProfile.
func (c *Client) AcceptTransfer(sk *[ed25519.PrivateKeySize]byte, op *SignedProfileOperation) error {
	return c.Enact(NewSign(sk, op), nil)
}

// Modify uses a secret key to associate name with profile. The caller must
// ensure that profile.Version is strictly greater than the version of the
// currently registered profile; it is usually good practice to increase the
// version by exactly one.
func (c *Client) Modify(sk *[ed25519.PrivateKeySize]byte, name []byte, profile *Profile) error {
	return c.Enact(NewSign(sk, OldSign(sk, MakeOperation(name, profile))), nil)
}

// VerifiyConsensus performs the low-level checks to see whether a set of
// statements made by the servers is sufficient to consider the state contained
// by them to be canonical.
func (c *Client) VerifyConsensus(signedHashOfStateMsgs []*SignedServerMessage) (
	rootHash []byte, err error) {
	consensusServers := make(map[uint64]struct{})
	freshnessServers := make(map[uint64]struct{})
	for _, signedMsg := range signedHashOfStateMsgs {
		msg := new(SignedServerMessage_ServerMessage)
		if err = proto.Unmarshal(signedMsg.Message, msg); err != nil {
			continue
		}
		server, ok := c.servers[*msg.Server]
		if !ok || server.pk.Ed25519 == nil {
			continue
		}
		var pk_ed [ed25519.PublicKeySize]byte
		copy(pk_ed[:], server.pk.Ed25519)
		var sig_ed [ed25519.SignatureSize]byte
		copy(sig_ed[:], signedMsg.Signature)
		if !ed25519.Verify(&pk_ed, append([]byte("msg\x00"), signedMsg.Message...), &sig_ed) {
			continue
		}
		if rootHash == nil {
			rootHash = msg.HashOfState
		} else if !bytes.Equal(rootHash, msg.HashOfState) {
			return nil, fmt.Errorf("verifyConsensus: state hashes differ")
		}
		consensusServers[*msg.Server] = struct{}{}
		if !time.Unix(int64(*msg.Time), 0).Add(c.freshnessThreshold).After(server.tlsConfig.Time()) {
			continue
		}
		freshnessServers[*msg.Server] = struct{}{}
	}
	if len(consensusServers) < c.consensusNumConfirmations {
		return nil, fmt.Errorf("not enough valid signatures for consensus (%d out of %d)", len(consensusServers), c.consensusNumConfirmations)
	}
	if len(freshnessServers) < c.freshnessNumConfirmations {
		return nil, fmt.Errorf("not enough fresh signatures (%d out of %d)", len(freshnessServers), c.freshnessNumConfirmations)
	}
	return rootHash, nil
}
