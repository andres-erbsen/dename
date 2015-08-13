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
	"fmt"
	. "github.com/andres-erbsen/dename/protocol"
	"github.com/gogo/protobuf/proto"
	"log"
	"net"
	"sync"
)

type ServerInfo struct {
	ID   uint64
	Addr string
	Profile_PublicKey
	IsCore        bool
	messageBroker *MessageBroker

	connMu sync.RWMutex
	conn   net.Conn // or nil
}

type serverNet interface {
	Broadcast(msg *BackendMessage)
	SendToServer(id uint64, msg *BackendMessage)
}

type subscriberManager interface {
	AddSubscriber(conn net.Conn)
}

type communicator struct {
	subscribers subscriberManager
	serverNet
	servers       map[uint64]*ServerInfo
	recallMessage func(uint64, uint64, uint64) *SignedServerMessage
	id            uint64
}

func (c *communicator) OnMessage(buf []byte, conn net.Conn) (err error) {
	request := new(BackendMessage)
	if err = proto.Unmarshal(buf, request); err != nil {
		log.Printf("protodecode BackendMessage from %v: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	if smsg := request.SignedServerMessage; smsg != nil {
		msg := new(Message)
		err = proto.Unmarshal(smsg.Message, &msg.SignedServerMessage_ServerMessage)
		if err != nil {
			log.Printf("protodecode ServerMessage from %v: %v", conn.RemoteAddr(), err)
			conn.Close()
			return
		}
		msg.SignedServerMessage = smsg
		if msg.Phase() == -1 {
			log.Printf("Message unknown phase from %x", *msg.Server)
			return
		}
		server, ok := c.servers[*msg.Server]
		if !ok {
			// log.Printf("Message from unknown server %x", *msg.Server)
			return
		}
		err = server.VerifySignature("msg", smsg.Message, smsg.Signature)
		if err != nil {
			log.Printf("invalid signature for %x from %v", *msg.Server, conn.RemoteAddr())
			conn.Close()
			return
		}
		if server.IsCore || *msg.Server == c.id || msg.Phase() == PHASE_HASH_STATE {
			c.servers[*msg.Server].messageBroker.OnReceive(msg)
		} else {
			log.Printf("Message for phase %d from non-core server %x", msg.Phase(), *msg.Server)
		}
	}
	if d := request.Download; d != nil {
		for _, phase := range d.Phase {
			for _, server := range d.Server {
				if smsg := c.recallMessage(d.GetRound(), phase, server); smsg != nil {
					writeMessage(conn, PBEncode(&BackendMessage{SignedServerMessage: smsg}))
				}
			}
		}
	}
	if request.GetSubscribe() {
		c.subscribers.AddSubscriber(conn)
	}
	return nil
}

var errStop = fmt.Errorf("Shutting down")

func (c *communicator) CollectFromCore(round uint64, phase int, reminder *SignedServerMessage) (map[uint64]*Message, error) {
	ret := make(map[uint64]*Message, len(c.servers))
	mbChannels := make([]chan *Message, 0, len(c.servers))
	for id, s := range c.servers {
		if !s.IsCore {
			continue
		}
		if smsg := c.recallMessage(round, uint64(phase), id); smsg != nil {
			msg := new(Message)
			msg.SignedServerMessage = smsg
			MustUnmarshal(smsg.Message, &msg.SignedServerMessage_ServerMessage)
			ret[*msg.Server] = msg
		} else {
			mbChannels = append(mbChannels, s.messageBroker.Collect(round, phase, reminder))
		}
	}
	for _, ch := range mbChannels {
		if msg := <-ch; msg != nil {
			ret[*msg.Server] = msg
		} else { // messageBroker has been shut down
			return nil, errStop
		}
	}
	return ret, nil
}

func (c *communicator) CollectWithThreshold(round uint64, phase, threshold int) (map[uint64]*Message, error) {
	ret, err := c.CollectFromCore(round, phase, nil)
	if err != nil || len(ret) >= threshold {
		return ret, err
	}

	// stack of defers: signal stop to workers, wait for shutdown, close collectChan
	collectChan := make(chan *Message)
	defer close(collectChan)
	var wg sync.WaitGroup
	defer wg.Wait()
	doneChan := make(chan struct{})
	defer close(doneChan)

	for id, s := range c.servers {
		if s.IsCore {
			continue
		}
		if smsg := c.recallMessage(round, uint64(phase), id); smsg != nil {
			msg := new(Message)
			msg.SignedServerMessage = smsg
			MustUnmarshal(smsg.Message, &msg.SignedServerMessage_ServerMessage)
			ret[*msg.Server] = msg
			continue
		}
		wg.Add(1)
		go func(s *ServerInfo) {
			defer wg.Done()
			select {
			case collectChan <- <-s.messageBroker.Collect(round, phase, nil):
			case <-doneChan:
			}
		}(s)
	}
	for len(ret) < threshold {
		if msg := <-collectChan; msg != nil {
			ret[*msg.Server] = msg
		} else { // messageBroker has been shut down
			return nil, errStop
		}
	}
	return ret, nil
}

func (c *communicator) NotifyAny(round uint64, phase int) chan struct{} {
	var doneOnce sync.Once
	done := make(chan struct{})
	for _, s := range c.servers {
		ch := s.messageBroker.Notify(round, phase)
		go func(ch chan struct{}) {
			<-ch
			doneOnce.Do(func() { close(done) })
		}(ch)
	}
	return done
}

func (c *communicator) StartWaitingFor(f func(*Message) (bool, bool)) {
	for _, s := range c.servers {
		s.messageBroker.StartWaitingFor(f)
	}
}
