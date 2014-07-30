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
	"testing"
	"time"
)

func TestMessageBrokerWaitOneMessage(t *testing.T) {
	mb := new(MessageBroker)
	ch := make(chan *Message)
	go func() {
		ch <- <-mb.Collect(7, PHASE_OPS, nil)
	}()
	var seven uint64 = 7
	msg := new(Message)
	msg.Round = &seven
	msg.Operations = []byte{}
	mb.OnReceive(msg)
	m := <-ch
	if m != msg {
		t.Fatal("Wrong message")
	}
}

func TestMessageBrokerBufferOneMessage(t *testing.T) {
	mb := new(MessageBroker)
	var seven uint64 = 7
	msg := new(Message)
	msg.Round = &seven
	msg.Operations = []byte{}
	mb.OnReceive(msg)
	m := <-mb.Collect(7, PHASE_OPS, nil)
	if m != msg {
		t.Fatal("Wrong message")
	}
}

func TestMessageBrokerWaitsForMessages(t *testing.T) {
	mb := new(MessageBroker)
	ch := make(chan struct{})
	go func() {
		<-mb.Collect(7, PHASE_OPS, nil)
		ch <- struct{}{}
	}()
	select {
	case _ = <-ch:
		t.Fatal("Got a message right away")
	case _ = <-time.After(1 * time.Millisecond):
	}
	// satisfy the collect call
	var seven uint64 = 7
	msg := new(Message)
	msg.Round = &seven
	msg.Operations = []byte{}
	mb.OnReceive(msg)
}

func TestMessageBrokerWaitsForMatchingMessagesInOrder(t *testing.T) {
	mb := &MessageBroker{stop: make(chan struct{})}
	var seven uint64 = 7
	msg1 := new(Message)
	msg1.Round = &seven
	msg1.Operations = []byte{}
	mb.OnReceive(msg1)
	ch := make(chan bool)
	go func() {
		<-mb.Collect(7, PHASE_HASH_STATE, nil)
		ch <- true
	}()
	msg2 := new(Message)
	msg2.Round = &seven
	msg2.Operations = []byte{}
	mb.OnReceive(msg2)
	select {
	case _ = <-ch:
		t.Fatal("Got a message right away")
	case _ = <-time.After(1 * time.Millisecond):
	}
	m1 := <-mb.Collect(7, PHASE_OPS, nil)
	if m1 != msg1 {
		t.Fatal("Wrong message")
	}
	m2 := <-mb.Collect(7, PHASE_OPS, nil)
	if m2 != msg2 {
		t.Fatal("Wrong message")
	}
	close(mb.stop)
}

func TestMessageBrokerBuffersMismatchingMessage(t *testing.T) {
	mb := new(MessageBroker)
	ch := make(chan *Message)
	go func() {
		ch <- <-mb.Collect(2, PHASE_HASH_STATE, nil)
	}()
	var seven uint64 = 7
	msg1 := new(Message)
	msg1.Round = &seven
	msg1.Operations = []byte{}
	mb.OnReceive(msg1)
	select {
	case _ = <-ch:
		t.Fatal("Got a message right away")
	case _ = <-time.After(1 * time.Millisecond):
	}
	m1 := <-mb.Collect(7, PHASE_OPS, nil)
	if m1 != msg1 {
		t.Fatal("Wrong message")
	}
	var two uint64 = 2
	msg2 := new(Message)
	msg2.Round = &two
	msg2.HashOfState = []byte{}
	mb.OnReceive(msg2)
	m2 := <-ch
	if m2 != msg2 {
		t.Fatal("Wrong message")
	}
}

func TestMessageBrokerNotifyReceiveCollect(t *testing.T) {
	mb := new(MessageBroker)
	var seven uint64 = 7
	msg := new(Message)
	msg.Round = &seven
	msg.Operations = []byte{}
	ch := mb.Notify(7, PHASE_OPS)
	mb.OnReceive(msg)
	select {
	case <-ch:
	case <-time.After(time.Millisecond):
		t.Fatal("did not notify")
	}
	select {
	case <-mb.Collect(7, PHASE_OPS, nil):
	case <-time.After(1 * time.Millisecond):
		t.Fatal("did not collect")
	}
}

func TestMessageBrokerReceiveNotifyCollect(t *testing.T) {
	mb := new(MessageBroker)
	var seven uint64 = 7
	msg := new(Message)
	msg.Round = &seven
	msg.Operations = []byte{}
	mb.OnReceive(msg)
	ch := mb.Notify(7, PHASE_OPS)
	select {
	case <-ch:
	case <-time.After(time.Millisecond):
		t.Fatal("did not notify")
	}
	select {
	case <-mb.Collect(7, PHASE_OPS, nil):
	case <-time.After(1 * time.Millisecond):
		t.Fatal("did not collect")
	}
}
