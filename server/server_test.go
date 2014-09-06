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
	"bytes"
	"code.google.com/p/goprotobuf/proto"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/agl/ed25519"
	. "github.com/andres-erbsen/dename/client"
	. "github.com/andres-erbsen/dename/protocol"
	"io/ioutil"
	mathrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"
)

type testNet struct {
	servers    map[uint64]*server
	homeServer uint64
	loss       float64
	sendWg     sync.WaitGroup
	sync.Mutex
}

func (n *testNet) Broadcast(msg *BackendMessage) {
	n.Lock()
	defer n.Unlock()
	for id, _ := range n.servers {
		go n.SendToServer(id, msg)
	}
}
func (n *testNet) SendToServer(id uint64, msg *BackendMessage) {
	n.Lock()
	if n.servers == nil {
		n.Unlock()
		return
	}
	n.sendWg.Add(1)
	defer n.sendWg.Done()
	n.Unlock()
	if id == n.homeServer || mathrand.Float64() >= n.loss {
		hs := n.servers[n.homeServer]
		n.servers[id].communicator.OnMessage(PBEncode(msg), mockConn(func(x []byte) (int, error) {
			if n.servers == nil {
				return len(x), nil
			}
			if id != n.homeServer || mathrand.Float64() >= n.loss {
				r := bytes.NewReader(x)
				l, err := binary.ReadUvarint(r)
				if err != nil {
					panic(err)
				}
				m := make([]byte, l)
				_, err = r.Read(m)
				if err != nil {
					panic(err)
				}
				hs.communicator.OnMessage(m, nil)
			}
			return len(x), nil
		}))
	}
}
func (n *testNet) shutdown() {
	n.Lock()
	n.sendWg.Wait()
	n.servers = nil
	n.Unlock()
}

type mockConn func([]byte) (int, error)

func (mockConn) Read([]byte) (int, error)         { panic("mockConn.read") }
func (c mockConn) Write(bs []byte) (int, error)   { return c(bs) }
func (mockConn) Close() error                     { return nil }
func (mockConn) LocalAddr() net.Addr              { panic("mockConn.LocalAddr") }
func (mockConn) RemoteAddr() net.Addr             { panic("mockConn.RemoteAddr") }
func (mockConn) SetDeadline(time.Time) error      { return nil }
func (mockConn) SetReadDeadline(time.Time) error  { return nil }
func (mockConn) SetWriteDeadline(time.Time) error { return nil }

func startServers(n uint, loss float64) (serverSlice []*server, cfg *Config, teardown func()) {
	dir, err := ioutil.TempDir("", "servertest")
	if err != nil {
		panic(err)
	}

	serverIDs := make([]uint64, n)
	servers := make(map[uint64]*server)
	pks := make(map[uint64]Profile_PublicKey)
	sks := make(map[uint64]*[ed25519.PrivateKeySize]byte)
	nets := make(map[uint64]*testNet)
	cfg = new(Config)
	cfg.Freshness = DefaultFreshness
	cfg.Server = make(map[string]*Server)
	for i := uint(0); i < n; i++ {
		pkEd, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		pk := Profile_PublicKey{Ed25519: pkEd[:]}
		id := pk.ID()
		pks[id] = pk
		serverIDs[i] = id
		sks[id] = sk
		cfg.Server[fmt.Sprint(id)] = &Server{PublicKey: base64.StdEncoding.EncodeToString(PBEncode(&pk))}
	}
	for i := uint(0); i < n; i++ {
		id := serverIDs[i]
		err = os.Mkdir(filepath.Join(dir, fmt.Sprintf("%x", id)), os.FileMode(0700))
		if err != nil {
			panic(err)
		}
		net := &testNet{servers: servers, homeServer: id, loss: loss}
		comm := &communicator{serverNet: net}
		comm.servers = make(map[uint64]*ServerInfo)
		for _, id := range serverIDs {
			comm.servers[id] = &ServerInfo{ID: id, Profile_PublicKey: pks[id], IsCore: true, messageBroker: &MessageBroker{serverID: id, servernet: net}}
		}
		fe := NewFrontend(INVITE_KEY)
		server, err := OpenServer(filepath.Join(dir, fmt.Sprintf("%x", id), "db"), sks[id], comm, fe, 0)
		if err != nil {
			panic(err)
		}
		for _, s := range comm.servers {
			s.messageBroker.stop = server.stop
		}
		servers[id] = server
		if servers[id].id != id {
			panic("server serverID generation fails contract")
		}
		nets[id] = net
	}
	for _, s := range servers {
		serverSlice = append(serverSlice, s)
		s.waitStop.Add(1)
		go s.Run()
	}
	return serverSlice, cfg, func() {
		for id, _ := range servers {
			nets[id].shutdown()
		}
		for _, s := range servers {
			close(s.stop)
		}
		for _, s := range servers {
			s.waitStop.Wait()
			s.db.Close()
		}
		os.RemoveAll(dir)
	}
}

func TestServerStartStop(t *testing.T) {
	_, _, teardown := startServers(3, 0)
	teardown()
}

func TestServerEmptyDoesNotCrashOnReads(*testing.T) {
	servers, _, teardown := startServers(3, 0)
	defer teardown()
	servers[0].frontend.handleRequest(&ClientMessage{PeekState: &true_})
	servers[0].frontend.handleRequest(&ClientMessage{ResolveName: []byte("nonexistent")})
}

func roundTrip(t *testing.T, cfg *Config, server *server, nameStr string) {
	name := []byte(nameStr)
	profile, sk, err := NewProfile(nil, nil)
	if err != nil {
		panic(err)
	}
	rqReply := server.frontend.handleRequest(&ClientMessage{
		ModifyProfile: NewSign(sk, MakeOperation(name, profile)),
		InviteCode:    mktoken(),
	})
	rootReply := server.frontend.handleRequest(&ClientMessage{PeekState: &true_})
	resolveReply := server.frontend.handleRequest(&ClientMessage{ResolveName: name})
	if len(resolveReply.LookupNodes) == 0 {
		t.Fatalf("No reply:\n%v\n%v\n%v", *rqReply, *rootReply, *resolveReply)
	}
	if !bytes.Equal(resolveReply.LookupNodes[len(resolveReply.LookupNodes)-1].Value, PBEncode(profile)) {
		t.Errorf("Profile is plain wrong")
	}
	client, err := NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	root, err := client.VerifyConsensus(rootReply.StateConfirmations)
	if err != nil {
		t.Fatal(err)
	}
	resolveProfileBs, err := VerifyResolveAgainstRoot(root, name, resolveReply.LookupNodes)
	if err != nil {
		t.Fatal(err)
	}
	resolveProfile := new(Profile)
	err = proto.Unmarshal(resolveProfileBs, resolveProfile)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(profile, resolveProfile) {
		t.Errorf("Verified profile does not match")
	}
}

func TestOneServer(t *testing.T) {
	servers, cfg, teardown := startServers(1, 0)
	defer teardown()
	roundTrip(t, cfg, servers[0], "John Smith")
}

func TestTwoServers(t *testing.T) {
	servers, cfg, teardown := startServers(2, 0)
	defer teardown()
	roundTrip(t, cfg, servers[1], "John Smith")
}

func TestSevenServers(t *testing.T) {
	servers, cfg, teardown := startServers(7, 0)
	roundTrip(t, cfg, servers[4], "John Smith")
	teardown()
}

func TestServerUnreliableNetwork(t *testing.T) {
	servers, cfg, teardown := startServers(2, .5)
	defer teardown()
	roundTrip(t, cfg, servers[1], "John Smith")
}

func createConfigs(t *testing.T, numCoreServers, numVerifiers, numSubscribers uint) (dirs []string, clientConfig *Config, teardown func()) {
	n := numCoreServers + numVerifiers + numSubscribers
	dir, err := ioutil.TempDir("", "servertest")
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]uint64, n)
	pks := make(map[uint64]*Profile_PublicKey, n)
	dirMap := make(map[uint64]string, n)
	dirs = make([]string, 0, n)
	configs := make(map[uint64]string, n)
	for i := uint(0); i < n; i++ {
		pkEd, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		pk := &Profile_PublicKey{Ed25519: pkEd[:]}
		id := pk.ID()
		ids[i] = id
		pks[id] = pk
		dir := filepath.Join(dir, fmt.Sprintf("%x", id))
		dirs = append(dirs, dir)
		dirMap[id] = dir
		err = os.Mkdir(dir, os.FileMode(0700))
		if err != nil {
			t.Fatal(err)
		}
		ioutil.WriteFile(filepath.Join(dirMap[id], "sk"), sk[:], os.FileMode(0600))
		ioutil.WriteFile(filepath.Join(dirMap[id], "invitekey"), INVITE_KEY, os.FileMode(0600))
		tlsCertPath, tlsKeyPath := filepath.Join(dir, "server.crt.pem"), filepath.Join(dir, "server.key.pem")
		putCert(tlsCertPath, tlsKeyPath)
		configs[id] = fmt.Sprintf(`[backend]
DataDirectory = %s
SigningKeyPath = %s
Listen = 127.0.0.1:198%d

[frontend]
InviteKeyPath = %s
TLSCertPath = %s
TLSKeyPath = %s
Listen = 127.0.0.1:144%d
`, dir, filepath.Join(dir, "sk"), i, filepath.Join(dir, "invitekey"), tlsCertPath, tlsKeyPath, i)
	}
	for left_i, left_id := range ids {
		putConf := func(i uint) {
			configs[left_id] += fmt.Sprintf(`
[server "127.0.0.1:198%d"]
PublicKey = %s
IsCore = %t
`, i, base64.StdEncoding.EncodeToString(PBEncode(pks[ids[i]])), i < numCoreServers)
		}
		for i := uint(0); i < numCoreServers+numVerifiers; i++ {
			putConf(i)
		}
		if uint(left_i) >= numCoreServers+numVerifiers { // put the server itself in its peers irrespectively of stuff
			putConf(uint(left_i))
		}
		ioutil.WriteFile(filepath.Join(dirMap[left_id], "denameserver.cfg"), []byte(configs[left_id]), os.FileMode(0600))
	}
	cfg := new(Config)
	cfg.Freshness = DefaultFreshness
	cfg.Server = make(map[string]*Server)
	for i, id := range ids {
		cfg.Server[fmt.Sprintf("127.0.0.1:144%d", i)] = &Server{PublicKey: base64.StdEncoding.EncodeToString(PBEncode(pks[id]))}
	}
	return dirs, cfg, func() {
		os.RemoveAll(dir)
	}
}

func startWithConfigAndBacknet(t *testing.T, numCoreServers, numVerifiers, numSubscribers uint) ([]*server, []string, *Config, func()) {
	dirs, cfg, teardown := createConfigs(t, numCoreServers, numVerifiers, numSubscribers)
	servers := make([]*server, 0, numCoreServers+numVerifiers+numSubscribers)
	for _, dir := range dirs {
		s := startFromConfigFile(filepath.Join(dir, "denameserver.cfg"))
		servers = append(servers, s)
	}
	return servers, dirs, cfg, func() {
		for _, s := range servers {
			close(s.stop)
			s.waitStop.Wait()
		}
		teardown()
	}
}

func TestServerConfigStartStop(t *testing.T) {
	_, _, _, teardown := startWithConfigAndBacknet(t, 3, 0, 0)
	teardown()
}

func TestServerBacknetRoundtrip(t *testing.T) {
	servers, _, cfg, teardown := startWithConfigAndBacknet(t, 3, 0, 0)
	defer teardown()
	roundTrip(t, cfg, servers[1], "John Smith")
}

func TestServerRestartSingle(t *testing.T) {
	dirs, cfg, teardown := createConfigs(t, 1, 0, 0)
	defer teardown()
	for i := 0; i < 3; i++ {
		server := startFromConfigFile(filepath.Join(dirs[0], "denameserver.cfg"))
		roundTrip(t, cfg, server, "alice "+fmt.Sprint(i))
		close(server.stop)
		server.waitStop.Wait()
		server.db.Close()
		if testing.Verbose() {
			fmt.Println("RESTARTING")
		}
	}
}

func TestServerRestartOneOfTwo(t *testing.T) {
	dirs, cfg, teardown := createConfigs(t, 2, 0, 0)
	defer teardown()
	constantServer := startFromConfigFile(filepath.Join(dirs[1], "denameserver.cfg"))
	server := startFromConfigFile(filepath.Join(dirs[0], "denameserver.cfg"))
	roundTrip(t, cfg, constantServer, "bob")
	for i := 0; i < 3; i++ {
		close(server.stop)
		server.waitStop.Wait()
		server.db.Close()
		if testing.Verbose() {
			fmt.Println("RESTARTING")
		}
		server = startFromConfigFile(filepath.Join(dirs[0], "denameserver.cfg"))
		roundTrip(t, cfg, server, "alice "+fmt.Sprint(i))
	}
	close(constantServer.stop)
	constantServer.waitStop.Wait()
	constantServer.db.Close()

	close(server.stop)
	server.waitStop.Wait()
	server.db.Close()
}

func frontendRoundTrip(t *testing.T, cfg *Config, name string) (*Profile, *[64]byte) {
	profile, sk, err := NewProfile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(cfg, nil, testing_tls_config)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Register(sk, []byte(name), profile, mktoken()); err != nil {
		t.Error(err)
	}
	lookupProfile, err := client.Lookup([]byte(name))
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(profile, lookupProfile) {
		t.Errorf("frontend lookup got wrong profile\n%v\n!=\n%v", lookupProfile, profile)
	}
	return profile, sk
}

func TestServerFrontendRoundtrip(t *testing.T) {
	_, _, cfg, teardown := startWithConfigAndBacknet(t, 3, 0, 0)
	defer teardown()
	frontendRoundTrip(t, cfg, "alice")
}

func TestServerProofOfAbsence(t *testing.T) {
	_, _, cfg, teardown := startWithConfigAndBacknet(t, 2, 0, 0)
	defer teardown()
	frontendRoundTrip(t, cfg, "alice")
	client, err := NewClient(cfg, nil, testing_tls_config)
	if err != nil {
		t.Fatal(err)
	}
	lookupProfile, err := client.Lookup([]byte("nonexistent"))
	if err != nil {
		t.Error(err)
	}
	if lookupProfile != nil {
		t.Errorf("frontend lookup got profile when there was none")
	}
}

func TestServerFrontendTransfer(t *testing.T) {
	_, _, cfg, teardown := startWithConfigAndBacknet(t, 3, 0, 0)
	defer teardown()
	_, sk := frontendRoundTrip(t, cfg, "alice")
	profile2, sk2, err := NewProfile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile2.Version = new(uint64)
	*profile2.Version = 2
	client, err := NewClient(cfg, nil, testing_tls_config)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AcceptTransfer(sk2, TransferProposal(sk, []byte("alice"), profile2)); err != nil {
		t.Error(err)
	}
}

func TestServerFrontendUnauthorizedTransfer(t *testing.T) {
	_, _, cfg, teardown := startWithConfigAndBacknet(t, 3, 0, 0)
	defer teardown()
	_, sk := frontendRoundTrip(t, cfg, "alice")
	profile2, sk2, err := NewProfile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(cfg, nil, testing_tls_config)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AcceptTransfer(sk, TransferProposal(sk, []byte("alice"), profile2)); err != ErrNotAuthorized {
		t.Error(err)
	}
	if err := client.AcceptTransfer(sk2, TransferProposal(sk2, []byte("alice"), profile2)); err != ErrNotAuthorized {
		t.Error(err)
	}
}

func TestServerFrontendExpiration(t *testing.T) {
	_, _, cfg, teardown := startWithConfigAndBacknet(t, 3, 0, 0)
	defer teardown()
	name := []byte("alice")
	client, err := NewClient(cfg, nil, testing_tls_config)
	if err != nil {
		t.Fatal(err)
	}
	profile, sk, err := NewProfile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	*profile.ExpirationTime = uint64(time.Now().Unix())
	for i := uint64(1); ; i++ { // try to register with as early expiration as possible
		if err := client.Register(sk, name, profile, mktoken()); err == nil {
			break
		} else if err != ErrNotAuthorized {
			t.Error(err)
		}
		*profile.ExpirationTime += i
	}
	profile2, sk2, err := NewProfile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for { // try to register another profile for the same name
		if err := client.Register(sk2, name, profile2, mktoken()); err == nil {
			break
		} else if err != ErrNotAuthorized {
			t.Error(err)
		}
	}
}

func TestServerFrontendRegisterBadExpiration(t *testing.T) {
	_, _, cfg, teardown := startWithConfigAndBacknet(t, 3, 0, 0)
	defer teardown()
	name := []byte("alice")
	profile, sk, err := NewProfile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(cfg, nil, testing_tls_config)
	if err != nil {
		t.Fatal(err)
	}
	*profile.ExpirationTime = 0
	if err := client.Register(sk, []byte(name), profile, mktoken()); err != ErrNotAuthorized {
		t.Error(err)
	}
	*profile.ExpirationTime = 1 << 62
	if err := client.Register(sk, []byte(name), profile, mktoken()); err != ErrNotAuthorized {
		t.Error(err)
	}
}

func TestServerFrontendChecksInvites(t *testing.T) {
	servers, _, cfg, teardown := startWithConfigAndBacknet(t, 1, 0, 0)
	defer teardown()
	profile, sk, err := NewProfile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile2, sk, err := NewProfile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(cfg, nil, testing_tls_config)
	if err != nil {
		t.Fatal(err)
	}
	for {
		// wait until the server is up
		_, err := client.Lookup(nil)
		if err == ErrCouldntVerify {
			break
		}
	}
	alice := []byte("alice")
	bob := []byte("bob")
	bad := [17]byte{'b', 'a', 'd'}
	err = client.Register(sk, alice, profile, bad[:])
	if err != ErrInviteInvalid {
		t.Error(err)
	}
	err = client.Register(sk, alice, profile, bad[:16])
	if err != ErrInviteInvalid {
		t.Error(err)
	}
	lookupProfile, err := client.Lookup(alice)
	if lookupProfile != nil {
		t.Errorf("invalid invite; lookup reply: %v (error: %v)", lookupProfile, err)
	}
	invite := mktoken()
	err = client.Register(sk, alice, profile2, invite)
	if err != nil {
		t.Error(err)
	}
	lookupProfile, err = client.Lookup(alice)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(profile2, lookupProfile) {
		t.Errorf("frontend lookup got wrong profile\n%v\n!=\n%v", lookupProfile, profile)
	}
	err = client.Register(sk, bob, profile2, invite)
	if err != ErrInviteUsed {
		t.Error(err)
	}
	lookupProfile, err = client.Lookup(bob)
	if lookupProfile != nil {
		t.Errorf("used invite; lookup reply: %v (error: %v)", lookupProfile, err)
	}
	servers[0].frontend.inviteMacKey = nil
	ted := []byte("ted")
	err = client.Register(sk, ted, profile, mktoken())
	if err != ErrRegistrationDisabled {
		t.Error(err)
	}
	lookupProfile, err = client.Lookup(ted)
	if lookupProfile != nil {
		t.Errorf("used invite; lookup reply: %v (error: %v)", lookupProfile, err)
	}
}

func TestServerVerifierSigns(t *testing.T) {
	_, _, cfg, teardown := startWithConfigAndBacknet(t, 1, 1, 0)
	defer teardown()
	profile, sk, err := NewProfile(nil, nil)
	name := []byte("alice")
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(cfg, nil, testing_tls_config)
	if err != nil {
		t.Fatal(err)
	}
	for {
		// wait until the server is up
		_, err := client.Lookup(nil)
		if err == ErrCouldntVerify {
			break
		}
		runtime.Gosched()
	}
	if err := client.Register(sk, []byte(name), profile, mktoken()); err != nil {
		t.Error(err)
	}
	var lookupProfile *Profile
	for {
		lookupProfile, err = client.Lookup([]byte(name))
		if err != ErrCouldntVerify {
			break
		}
		runtime.Gosched()
	}
	if !reflect.DeepEqual(profile, lookupProfile) {
		t.Errorf("frontend lookup got wrong profile\n%v\n!=\n%v", lookupProfile, profile)
	}
}

func TestServerVerifierWaits(t *testing.T) {
	servers, _, cfg, teardown := startWithConfigAndBacknet(t, 1, 1, 0)
	servers[1].consensusThreshold = 2 // verifier requires both verifier and core (racy set)
	defer teardown()
	profile, sk, err := NewProfile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	verifier := cfg.Server["127.0.0.1:1441"]
	delete(cfg.Server, "127.0.0.1:1441")
	coreClient, err := NewClient(cfg, nil, testing_tls_config)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server["127.0.0.1:1441"] = verifier
	cfg.Server["unreachable"] = cfg.Server["127.0.0.1:1440"]
	delete(cfg.Server, "127.0.0.1:1440")
	verifierClient, err := NewClient(cfg, nil, testing_tls_config)
	if err != nil {
		t.Fatal(err)
	}

	// wait until the server is up
	for {
		_, err := coreClient.Lookup(nil)
		if err == ErrCouldntVerify {
			break
		}
		runtime.Gosched()
	}

	// do a profile update to make sure verifier has fully initialized.
	if err := coreClient.Register(sk, []byte("bob"), profile, mktoken()); err != nil {
		t.Fatal(err)
	}
	for {
		_, err := verifierClient.Lookup([]byte("bob"))
		if err == nil {
			break
		}
		runtime.Gosched()
	}

	name := []byte("alice")
	if err := coreClient.Register(sk, []byte(name), profile, mktoken()); err != nil {
		t.Fatal(err)
	}
	// Lookup through the verifier, requiring both signatures
	// It should never return ErrCouldntVerify because the verifier
	// should not switch to the new root without 2 signatures
	var lookupProfile *Profile
	for {
		lookupProfile, err = verifierClient.Lookup([]byte(name))
		if err != nil {
			t.Error(err)
		}
		if lookupProfile != nil {
			break
		}
		runtime.Gosched()
	}
	if !reflect.DeepEqual(profile, lookupProfile) {
		t.Errorf("frontend lookup got wrong profile\n%v\n!=\n%v", lookupProfile, profile)
	}
}

func TestServerSubscriberSigns(t *testing.T) {
	servers, _, cfg, teardown := startWithConfigAndBacknet(t, 1, 0, 1)
	defer teardown()
	serverAddr := "127.0.0.1:1440"
	subscriberAddr := "127.0.0.1:1441"
	serverPK := cfg.Server[serverAddr]
	delete(cfg.Server, serverAddr)
	if len(cfg.Server) != 1 {
		t.Fatalf("Could not delete core server from client config")
	}
	profile, sk, err := NewProfile(nil, nil)
	name := []byte("alice")
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(cfg, nil, testing_tls_config)
	if err != nil {
		t.Fatal(err)
	}
	for {
		// wait until the server is up
		_, err := client.Lookup(nil)
		if err == ErrCouldntVerify {
			break
		}
	}
	cfg.Server[serverAddr] = serverPK
	if len(cfg.Server) != 2 {
		t.Fatalf("Could not add core server to client config")
	}
	client, err = NewClient(cfg, nil, testing_tls_config)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Register(sk, []byte(name), profile, mktoken()); err != nil {
		t.Error(err)
	}
	delete(cfg.Server, serverAddr)
	if len(cfg.Server) != 1 {
		t.Fatalf("Could not delete core server from client config")
	}
	client, err = NewClient(cfg, nil, testing_tls_config)
	if err != nil {
		t.Fatal(err)
	}
	var lookupProfile *Profile
	for {
		lookupProfile, err = client.Lookup([]byte(name))
		if err != ErrCouldntVerify {
			break
		}
	}
	if !reflect.DeepEqual(profile, lookupProfile) {
		t.Errorf("frontend lookup got wrong profile\n%v\n!=\n%v", lookupProfile, profile)
	}
	// close the subscriber, check that the main server can still continue
	close(servers[1].stop)
	servers[1].waitStop.Wait()
	servers[1].stop = make(chan struct{}) // for teardown()

	cfg.Server[serverAddr] = serverPK
	if len(cfg.Server) != 2 {
		t.Fatalf("Could not add core server to client config")
	}
	delete(cfg.Server, subscriberAddr)
	if len(cfg.Server) != 1 {
		t.Fatalf("Could not delete subscriber from client config")
	}
	frontendRoundTrip(t, cfg, "bob")
}

func BenchmarkServerOneServer(b *testing.B) {
	b.StopTimer()
	servers, _, teardown := startServers(1, 0)
	defer teardown()
	var wg sync.WaitGroup
	profile, sk, err := NewProfile(nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	rqs := make([]*ClientMessage, b.N)
	for i := 0; i < b.N; i++ {
		rqs[i] = &ClientMessage{ModifyProfile: NewSign(sk, MakeOperation([]byte(fmt.Sprint(i)), profile)), InviteCode: mktoken()}
	}
	b.StartTimer()
	wg.Add(b.N)
	for i := 0; i < b.N; i++ {
		go func(rq *ClientMessage) {
			servers[0].frontend.handleRequest(rq)
			wg.Done()
		}(rqs[i])
	}
	wg.Wait()
	b.StopTimer()
}
