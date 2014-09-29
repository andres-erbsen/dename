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
	"bufio"
	. "github.com/andres-erbsen/dename/protocol"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type backNet struct {
	servers map[uint64]*ServerInfo
	handler func([]byte, net.Conn)

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
func (b *backNet) listenBackend(address string) error {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer b.waitStop.Done()
	defer ln.Close()
	go func() {
		<-b.stop
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
			log.Printf("read on %v: %v", conn.RemoteAddr(), readHandleLoop(conn, 1<<30, b.handler, b.stop))
			b.waitStop.Done()
		}(conn)
	}
}

func readHandleLoop(conn net.Conn, maxSize int, handler func([]byte, net.Conn), stop chan struct{}) error {
	defer conn.Close()
	go func() {
		<-stop
		conn.Close()
	}()
	reader := bufio.NewReader(conn)
	for {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		size, err := binary.ReadUvarint(reader)
		if err != nil {
			select {
			case <-stop:
				return errStop
			default:
				return err
			}
		}
		if size > uint64(maxSize) {
			return fmt.Errorf("readHandleLoop: record too big (%d > %d)", size, uint64(maxSize))
		}
		buf := make([]byte, size)
		_, err = io.ReadFull(reader, buf)
		select {
		case <-stop:
			return errStop
		default:
			if err != nil {
				return err
			}
		}
		handler(buf, conn)
	}
}

func (b *backNet) Broadcast(msg *BackendMessage) {
	for id, _ := range b.servers {
		go b.SendToServer(id, msg)
	}

	b.RLock()
	for conn := range b.subscribers {
		go b.sendToSubscriber(conn, msg)
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
				log.Printf("read on %x (%v): %v", id, conn.RemoteAddr(), readHandleLoop(conn, 1<<30, b.handler, b.stop))
				b.waitStop.Done()
			}(conn)
		} else {
			conn.Close()
			conn = server.conn
		}
		server.connMu.Unlock()
	}

	if err := writeMessage(conn, PBEncode(msg)); err != nil {
		log.Printf("Lost connection to %x: %v", id, err)
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
