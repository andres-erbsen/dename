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
	"bufio"
	"encoding/binary"
	"fmt"
	. "github.com/andres-erbsen/dename/protocol"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type backNet struct {
	servers map[uint64]*ServerInfo
	handler func([]byte, net.Conn) error

	sync.RWMutex
	subscribers map[net.Conn]struct{}

	stop     chan struct{}
	waitStop *sync.WaitGroup
}

func (b *backNet) AddSubscriber(conn net.Conn) {
	b.Lock()
	b.subscribers[conn] = struct{}{}
	b.Unlock()
}

// caller MUST call b.waitStop.Add(1) first
func (b *backNet) listenBackend(ln net.Listener) error {
	defer b.waitStop.Done()
	ret := make(chan struct{})
	defer close(ret)

	b.waitStop.Add(1)
	go func() {
		defer b.waitStop.Done()
		select {
		case <-b.stop:
		case <-ret:
		}
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-b.stop:
				return nil
			default:
				continue
			}
		}
		b.waitStop.Add(1)
		go func(conn net.Conn) {
			log.Printf("backnet on %v: %v", conn.RemoteAddr(), b.readHandleLoop(conn))
			b.waitStop.Done()
		}(conn)
	}
}

func (b *backNet) readHandleLoop(conn net.Conn) error {
	ret := make(chan struct{})
	defer close(ret)

	b.waitStop.Add(1)
	go func() {
		defer b.waitStop.Done()
		select {
		case <-b.stop:
		case <-ret:
		}
		conn.Close()
	}()
	reader := bufio.NewReader(conn)
	for {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		size, err := binary.ReadUvarint(reader)
		if err != nil {
			select {
			case <-b.stop:
				return nil
			default:
				return err
			}
		}
		maxSize := 1 << 24
		if size > uint64(maxSize) {
			return fmt.Errorf("readHandleLoop: record too big (%d > %d)", size, uint64(maxSize))
		}
		buf := make([]byte, size)
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			select {
			case <-b.stop:
				return nil
			default:
				return err
			}
		}
		if err = b.handler(buf, conn); err != nil {
			return err
		}
	}
}

func (b *backNet) Broadcast(msg *BackendMessage) {
	for id, _ := range b.servers {
		b.waitStop.Add(1)
		go func(id uint64) {
			b.SendToServer(id, msg)
			b.waitStop.Done()
		}(id)
	}

	b.RLock()
	for conn := range b.subscribers {
		b.waitStop.Add(1)
		go func(conn net.Conn) {
			b.sendToSubscriber(conn, msg)
			b.waitStop.Done()
		}(conn)
	}
	b.RUnlock()
}

func (b *backNet) SendToServer(id uint64, msg *BackendMessage) {
	server := b.servers[id]
	var conn net.Conn

	server.connMu.RLock()
	conn = server.conn
	server.connMu.RUnlock()

	if conn == nil {
		var err error
		conn, err = net.Dial("tcp", b.servers[id].Addr)
		if err != nil {
			log.Printf("Dial %x on %v: %v", id, b.servers[id].Addr, err)
			return
		}
		server.connMu.Lock()
		if server.conn == nil {
			server.conn = conn
			b.waitStop.Add(1)
			go func(conn net.Conn) {
				log.Printf("backnet send on %x (%v): %v", id, conn.RemoteAddr(), b.readHandleLoop(conn))
				b.waitStop.Done()
			}(conn)
		} else {
			conn.Close()
			conn = server.conn
		}
		server.connMu.Unlock()
	}

	if err := writeMessage(conn, PBEncode(msg)); err != nil {
		log.Printf("Lost connection to %x <%s>: %v", id, b.servers[id].Addr, err)
		server.connMu.Lock()
		if server.conn == conn {
			server.conn = nil
		}
		server.connMu.Unlock()
		conn.Close()
	}
}

func (b *backNet) sendToSubscriber(conn net.Conn, msg *BackendMessage) {
	if err := writeMessage(conn, PBEncode(msg)); err != nil {
		b.Lock()
		delete(b.subscribers, conn)
		b.Unlock()
		conn.Close()
	}
}

func writeMessage(conn net.Conn, msgData []byte) (err error) {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(Frame(msgData))
	return
}
