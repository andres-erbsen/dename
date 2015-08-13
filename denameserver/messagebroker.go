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

package denameserver

import (
	. "github.com/andres-erbsen/dename/protocol"
	"sync"
	"time"
)

type MessageBroker struct {
	serverID  uint64
	listeners []func(*Message) (bool, bool)
	messages  []*Message
	servernet serverNet
	subscribe bool
	sync.Mutex
	stop chan struct{}
}

const DOWNLOAD_INTERVAL = 300 * time.Millisecond

func (mb *MessageBroker) Collect(round uint64, phase int, reminder *SignedServerMessage) chan *Message {
	retCh := make(chan *Message, 1)
	doneCh := make(chan struct{})
	var once sync.Once
	closeChannels := func() {
		close(retCh)
		close(doneCh)
	}
	mb.StartWaitingFor(func(msg *Message) (bool, bool) {
		if *msg.Round == round && msg.Phase() == phase {
			retCh <- msg
			once.Do(closeChannels)
			return true, true
		}
		return false, false
	})
	go func() {
		for {
			select {
			case <-mb.stop:
				mb.Lock()
				mb.listeners = nil
				mb.messages = nil
				once.Do(closeChannels)
				mb.Unlock()
				return
			case <-doneCh:
				return
			case <-time.After(DOWNLOAD_INTERVAL):
				mb.servernet.SendToServer(mb.serverID, &BackendMessage{
					Download: &BackendMessage_MessageID{
						Round:  &round,
						Phase:  []uint64{uint64(phase)},
						Server: []uint64{mb.serverID},
					},
					SignedServerMessage: reminder,
					Subscribe:           &mb.subscribe,
				})
			}
		}
	}()
	return retCh
}

func (mb *MessageBroker) Notify(round uint64, phase int) chan struct{} {
	ch := make(chan struct{})
	mb.StartWaitingFor(func(msg *Message) (bool, bool) {
		if *msg.Round == round && (*msg.Round > round || msg.Phase() >= phase) {
			close(ch)
			return true, false
		}
		return false, false
	})
	return ch
}

func (mb *MessageBroker) StartWaitingFor(callback func(*Message) (bool, bool)) {
	mb.Lock()
	defer mb.Unlock()
	for i := 0; i < len(mb.messages); i++ {
		consumeCallback, consumeMessage := callback(mb.messages[i])
		if consumeMessage {
			mb.messages = append(mb.messages[:i], mb.messages[i+1:]...)
		}
		if consumeCallback {
			return
		}
	}
	mb.listeners = append(mb.listeners, callback)
}

func (mb *MessageBroker) OnReceive(msg *Message) {
	mb.Lock()
	defer mb.Unlock()
	for i := len(mb.listeners) - 1; i >= 0; i-- {
		consumeCallback, consumeMessage := mb.listeners[i](msg)
		if consumeCallback {
			mb.listeners = append(mb.listeners[:i], mb.listeners[i+1:]...)
		}
		if consumeMessage {
			return
		}
	}
	mb.messages = append(mb.messages, msg)
}
