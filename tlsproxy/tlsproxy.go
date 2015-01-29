package tlsproxy

import (
	_ "crypto/sha512" // for TLS
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/andres-erbsen/chatterbox/transport"
	. "github.com/andres-erbsen/dename/protocol"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"
)

type TLSProxy struct {
	connectAddr string
	connectPK   *[32]byte

	timeout      time.Duration
	maxFrameSize int

	wg   sync.WaitGroup
	stop chan struct{}
}

func RunTLSProxy(tlsCertPath, tlsKeyPath, listenAddr, connectAddr, connectPKPath string, maxFrameSize int) (*TLSProxy, error) {
	cert, err := tls.LoadX509KeyPair(tlsCertPath, tlsKeyPath)
	if err != nil {
		return nil, err
	}
	var connectPK [32]byte
	connectPKData, err := ioutil.ReadFile(connectPKPath)
	if err != nil {
		return nil, err
	}
	if len(connectPKData) != 32 {
		return nil, fmt.Errorf("tlsproxy: read transport pk: expected 32 bytes, got %d", len(connectPKData))
	}
	copy(connectPK[:], connectPKData)
	return RunTLSProxyWith(cert, listenAddr, connectAddr, &connectPK, maxFrameSize)
}

func RunTLSProxyWith(cert tls.Certificate, listenAddr, connectAddr string, connectPK *[32]byte, maxFrameSize int) (*TLSProxy, error) {
	config := tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ln, err := tls.Listen("tcp", listenAddr, &config)
	if err != nil {
		return nil, err
	}

	t := &TLSProxy{
		connectAddr: connectAddr,
		connectPK:   connectPK,

		timeout: time.Second,
		stop:    make(chan struct{}),
	}
	t.wg.Add(1)
	go func() { t.AcceptLoop(ln); t.wg.Done() }()
	return t, nil
}

func (t *TLSProxy) Stop() {
	close(t.stop)
	t.wg.Wait()
	return
}

func (t *TLSProxy) AcceptLoop(ln net.Listener) {
	ret := make(chan struct{})
	defer close(ret)

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		select {
		case <-t.stop:
		case <-ret:
		}
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-t.stop:
				return
			default:
				log.Printf("tlsproxy accept: %s", err)
			}
		}
		t.wg.Add(1)
		go func() { t.Client(conn); t.wg.Done() }()
	}
}

func (t *TLSProxy) Client(inConn net.Conn) {
	plainconn, err := net.Dial("tcp", t.connectAddr)
	if err != nil {
		log.Printf("tlsproxy dial %s: %s", t.connectAddr, err)
		return
	}
	plainconn.SetDeadline(time.Now().Add(time.Second))
	outConn, _, err := transport.Handshake(plainconn, nil, nil, t.connectPK, 1<<12)
	if err != nil {
		plainconn.Close()
		log.Printf("tlsproxy transport handshake: %s", err)
	}
	t.wg.Add(2)
	go func() { t.ClientIncoming(inConn, outConn); t.wg.Done() }()
	go func() { t.ClientOutgoing(inConn, outConn); t.wg.Done() }()
}

func (t *TLSProxy) ClientIncoming(inConn net.Conn, outConn *transport.Conn) {
	ret := make(chan struct{})
	defer close(ret)

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		select {
		case <-t.stop:
		case <-ret:
		}
		inConn.Close()
		outConn.Close()
	}()

	buf := make([]byte, t.maxFrameSize)
	for {
		inConn.SetReadDeadline(time.Now().Add(t.timeout))
		size, err := binary.ReadUvarint(byteReader{inConn})
		if err != nil {
			select {
			case <-t.stop:
			default:
				log.Printf("tlsproxy read length from tls: %s", err)
			}
			return
		}
		if size > uint64(t.maxFrameSize) {
			log.Printf("tlsproxy %s: record too big (%d > %d)", inConn.RemoteAddr(), size, uint64(t.maxFrameSize))
			return
		}
		_, err = io.ReadFull(inConn, buf[:size])
		if err != nil {
			select {
			case <-t.stop:
			default:
				log.Printf("tlsproxy read from tls: %s", err)
			}
			return
		}

		outConn.SetWriteDeadline(time.Now().Add(t.timeout))
		_, err = outConn.WriteFrame(buf[:size])
		if err != nil {
			select {
			case <-t.stop:
			default:
				log.Printf("tlsproxy write to transport: %s", err)
			}
			return
		}
	}
}

func (t *TLSProxy) ClientOutgoing(inConn net.Conn, outConn *transport.Conn) {
	ret := make(chan struct{})
	defer close(ret)

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		select {
		case <-t.stop:
		case <-ret:
		}
		inConn.Close()
		outConn.Close()
	}()

	buf := make([]byte, t.maxFrameSize)
	for {
		outConn.SetReadDeadline(time.Now().Add(t.timeout))
		n, err := outConn.ReadFrame(buf)
		if err != nil {
			select {
			case <-t.stop:
			default:
				log.Printf("tlsproxy read from transport: %s", err)
			}
			return
		}

		inConn.SetWriteDeadline(time.Now().Add(t.timeout))
		_, err = inConn.Write(Frame(buf[:n]))
		if err != nil {
			select {
			case <-t.stop:
			default:
				log.Printf("tlsproxy write to tls: %s", err)
			}
			return
		}
	}
}

type byteReader struct{ io.Reader }

func (r byteReader) ReadByte() (byte, error) {
	var ret [1]byte
	_, err := io.ReadFull(r, ret[:])
	return ret[0], err
}
