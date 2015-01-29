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
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/agl/ed25519"
	. "github.com/andres-erbsen/dename/client"
	. "github.com/andres-erbsen/dename/protocol"
	"github.com/andres-erbsen/dename/server/testutil"
	"github.com/gogo/protobuf/proto"
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
		fe := NewFrontend()
		fe.inviteMacKey = testutil.INVITE_KEY
		fe.isCore = true
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
			s.Shutdown()
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

func roundTrip(t *testing.T, cfg *Config, server *server, name string) {
	profile, sk, err := NewProfile(nil, nil)
	if err != nil {
		panic(err)
	}
	rqReply := server.frontend.handleRequest(&ClientMessage{
		ModifyProfile: NewSign(sk, MakeOperation(name, profile)),
		InviteCode:    testutil.MakeToken(),
	})
	rootReply := server.frontend.handleRequest(&ClientMessage{PeekState: &true_})
	resolveReply := server.frontend.handleRequest(&ClientMessage{ResolveName: []byte(name)})
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

func startWithConfigAndBacknet(t *testing.T, numCoreServers, numVerifiers, numSubscribers uint) ([]*server, []string, *Config, func()) {
	dirs, cfg, teardown := testutil.CreateConfigs(t, numCoreServers, numVerifiers, numSubscribers)
	servers := make([]*server, 0, numCoreServers+numVerifiers+numSubscribers)
	for _, dir := range dirs {
		s := StartFromConfigFile(filepath.Join(dir, "denameserver.cfg"))
		servers = append(servers, s)
	}
	return servers, dirs, cfg, func() {
		for _, s := range servers {
			s.Shutdown()
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
	dirs, cfg, teardown := testutil.CreateConfigs(t, 1, 0, 0)
	defer teardown()
	for i := 0; i < 3; i++ {
		server := StartFromConfigFile(filepath.Join(dirs[0], "denameserver.cfg"))
		roundTrip(t, cfg, server, "alice "+fmt.Sprint(i))
		server.Shutdown()
		if testing.Verbose() {
			fmt.Println("RESTARTING")
		}
	}
}

func TestServerRestartOneOfTwo(t *testing.T) {
	dirs, cfg, teardown := testutil.CreateConfigs(t, 2, 0, 0)
	defer teardown()
	constantServer := StartFromConfigFile(filepath.Join(dirs[1], "denameserver.cfg"))
	server := StartFromConfigFile(filepath.Join(dirs[0], "denameserver.cfg"))
	roundTrip(t, cfg, constantServer, "bob")
	for i := 0; i < 3; i++ {
		server.Shutdown()
		if testing.Verbose() {
			fmt.Println("RESTARTING")
		}
		server = StartFromConfigFile(filepath.Join(dirs[0], "denameserver.cfg"))
		roundTrip(t, cfg, server, "alice "+fmt.Sprint(i))
	}
	constantServer.Shutdown()
	server.Shutdown()
}

func chopSingleServer(cfg *Config) (restore func()) {
	cfgServerSingle := make(map[string]*Server)
	for k, v := range cfg.Server {
		cfgServerSingle[k] = v
		break
	}
	cfgServerBackup := cfg.Server
	cfg.Server = cfgServerSingle
	return func() {
		cfg.Server = cfgServerBackup
	}
}

func frontendRoundTrip(t *testing.T, cfg *Config, name string) (*Profile, *[64]byte) {
	profile, sk, err := NewProfile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chopSingleServer(cfg)() // chop now, defer restore
	client, err := NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Register(sk, name, profile, testutil.MakeToken()); err != nil {
		t.Error(err)
	}
	lookupProfile, err := client.Lookup(name)
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
	chopSingleServer(cfg)
	defer teardown()
	frontendRoundTrip(t, cfg, "alice")
	client, err := NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	lookupProfile, reply, err := client.LookupReply("nonexistent")
	if err != nil {
		t.Errorf("%s\n%v\n%x\n", err, reply, PBEncode(reply))
	}
	if lookupProfile != nil {
		t.Errorf("frontend lookup got profile when there was none")
	}

	frontendRoundTrip(t, cfg, "0")
	lookupProfile, reply, err = client.LookupReply("missing")
	if err != nil {
		t.Errorf("%s\n%v\n%x\n", err, reply, PBEncode(reply))
	}
	if lookupProfile != nil {
		t.Errorf("frontend lookup got profile when there was none")
	}
}

func TestServerNilNameProofOfAbsence(t *testing.T) {
	var rq_orig, rq_unmarshal ClientMessage
	rq_orig.ResolveName = []byte("")
	err := proto.Unmarshal(PBEncode(&rq_orig), &rq_unmarshal)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rq_orig.ResolveName, rq_unmarshal.ResolveName) {
		t.Skipf("Lookup of \"\" (emptystring) broken due to protobuf issues (%#v -> encode -> decode -> %#v)", rq_orig.ResolveName, rq_unmarshal.ResolveName)
	}

	_, _, cfg, teardown := startWithConfigAndBacknet(t, 2, 0, 0)
	chopSingleServer(cfg)
	defer teardown()
	frontendRoundTrip(t, cfg, "alice")
	client, err := NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	lookupProfile, err := client.Lookup("nonexistent")
	if err != nil {
		t.Error(err)
	}
	if lookupProfile != nil {
		t.Errorf("frontend lookup got profile when there was none")
	}

	frontendRoundTrip(t, cfg, "0")
	lookupProfile, err = client.Lookup("")
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
	chopSingleServer(cfg)
	_, sk := frontendRoundTrip(t, cfg, "alice")
	profile2, sk2, err := NewProfile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile2.Version = new(uint64)
	*profile2.Version = 2
	client, err := NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AcceptTransfer(sk2, TransferProposal(sk, "alice", profile2)); err != nil {
		t.Error(err)
	}
}

func TestServerFrontendUnauthorizedTransfer(t *testing.T) {
	_, _, cfg, teardown := startWithConfigAndBacknet(t, 3, 0, 0)
	defer teardown()
	chopSingleServer(cfg)
	correctProfile, sk := frontendRoundTrip(t, cfg, "alice")
	profile2, sk2, err := NewProfile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AcceptTransfer(sk, TransferProposal(sk, "alice", profile2)); err != ErrNotAuthorized {
		t.Errorf("unauthorized transfer returned %s", err)
	}
	lookupProfile, reply, err := client.LookupReply("alice")
	if err != nil {
		t.Errorf("lookup failed: %s\n%v\n%x\n", err, reply, PBEncode(reply))
	} else if !reflect.DeepEqual(lookupProfile, correctProfile) {
		t.Errorf("unauthorized transfer succeeded")
	}
	if err := client.AcceptTransfer(sk2, TransferProposal(sk2, "alice", profile2)); err != ErrNotAuthorized {
		t.Errorf("unauthorized transfer returned %s", err)
	}
	lookupProfile, err = client.Lookup("alice")
	if err != nil {
		t.Errorf("lookup failed: %s\n%v\n%x\n", err, reply, PBEncode(reply))
	} else if !reflect.DeepEqual(lookupProfile, correctProfile) {
		t.Errorf("unauthorized transfer succeeded")
	}
}

func TestServerFrontendExpiration(t *testing.T) {
	_, _, cfg, teardown := startWithConfigAndBacknet(t, 3, 0, 0)
	chopSingleServer(cfg)
	defer teardown()
	name := "alice"
	client, err := NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile, sk, err := NewProfile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	*profile.ExpirationTime = uint64(time.Now().Unix())
	for i := uint64(1); ; i++ { // try to register with as early expiration as possible
		if err := client.Register(sk, name, profile, testutil.MakeToken()); err == nil {
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
		if err := client.Register(sk2, name, profile2, testutil.MakeToken()); err == nil {
			break
		} else if err != ErrNotAuthorized {
			t.Error(err)
		}
		runtime.Gosched()
	}
}

func TestServerFrontendRegisterBadExpiration(t *testing.T) {
	_, _, cfg, teardown := startWithConfigAndBacknet(t, 3, 0, 0)
	defer teardown()
	name := "alice"
	profile, sk, err := NewProfile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	*profile.ExpirationTime = 0
	if err := client.Register(sk, name, profile, testutil.MakeToken()); err != ErrNotAuthorized {
		t.Error(err)
	}
	*profile.ExpirationTime = 1 << 62
	if err := client.Register(sk, name, profile, testutil.MakeToken()); err != ErrNotAuthorized {
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
	client, err := NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	alice := "alice"
	bob := "bob"
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
	invite := testutil.MakeToken()
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
	ted := "ted"
	err = client.Register(sk, ted, profile, testutil.MakeToken())
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
	name := "alice"
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Register(sk, name, profile, testutil.MakeToken()); err != nil {
		t.Error(err)
	}
	var lookupProfile *Profile
	for {
		lookupProfile, err = client.Lookup(name)
		if lookupProfile != nil {
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
	coreClient, err := NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server["127.0.0.1:1441"] = verifier
	cfg.Server["unreachable"] = cfg.Server["127.0.0.1:1440"]
	delete(cfg.Server, "127.0.0.1:1440")
	verifierClient, err := NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// do a profile update to make sure verifier has fully initialized.
	if err := coreClient.Register(sk, "bob", profile, testutil.MakeToken()); err != nil {
		t.Fatal(err)
	}
	for {
		_, err := verifierClient.Lookup("bob")
		if err == nil {
			break
		}
		runtime.Gosched()
	}

	name := "alice"
	if err := coreClient.Register(sk, name, profile, testutil.MakeToken()); err != nil {
		t.Fatal(err)
	}
	// Lookup through the verifier, requiring both signatures
	// It should never return ErrCouldntVerify because the verifier
	// should not switch to the new root without 2 signatures
	var lookupProfile *Profile
	for {
		lookupProfile, err = verifierClient.Lookup(name)
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
	subscriberPK := cfg.Server[subscriberAddr]
	delete(cfg.Server, subscriberAddr)
	if len(cfg.Server) != 1 {
		t.Fatalf("Could not delete subscriber from client config")
	}
	client, err := NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	name := "alice"
	frontendRoundTrip(t, cfg, name)
	profile, err := client.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}

	cfg.Server[subscriberAddr] = subscriberPK
	if len(cfg.Server) != 2 {
		t.Fatalf("Could not add subscriber to client config")
	}
	delete(cfg.Server, serverAddr)
	if len(cfg.Server) != 1 {
		t.Fatalf("Could not delete core server from client config")
	}
	client, err = NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var lookupProfile *Profile
	for lookupProfile == nil {
		var lookupReply *ClientReply
		lookupProfile, lookupReply, err = client.LookupReply(name)
		if lookupReply == nil {
			t.Fatal(err)
		}
		if lookupReply.LookupNodes != nil && err != nil {
			// only check th error if the server returns /something/ -- it may
			// be justuninitialized
			t.Errorf("reply: %v\n reply hex: %x\n", lookupReply, PBEncode(lookupReply))
			t.Fatal(err)
		}
		runtime.Gosched()
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
		t.Fatalf("could not delete subscriber from client config")
	}
	frontendRoundTrip(t, cfg, "bob")
}

func TestServerVerifierDoesNotHandleUpdates(t *testing.T) {
	servers, _, cfg, teardown := startWithConfigAndBacknet(t, 1, 1, 0)
	servers[1].consensusThreshold = 2 // verifier requires both verifier and core (racy set)
	defer teardown()
	profile, sk, err := NewProfile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	verifier := cfg.Server["127.0.0.1:1441"]
	delete(cfg.Server, "127.0.0.1:1441")
	coreClient, err := NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server["127.0.0.1:1441"] = verifier
	cfg.Server["unreachable"] = cfg.Server["127.0.0.1:1440"]
	delete(cfg.Server, "127.0.0.1:1440")
	verifierClient, err := NewClient(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// do a profile update to make sure verifier has fully initialized.
	if err := coreClient.Register(sk, "bob", profile, testutil.MakeToken()); err != nil {
		t.Fatal(err)
	}
	var newProfile *Profile
	for {
		newProfile, err = verifierClient.Lookup("bob")
		if newProfile != nil {
			break
		}
		runtime.Gosched()
	}

	newVersion := uint64(10)
	newProfile.Version = &newVersion
	if err := verifierClient.Modify(sk, "bob", newProfile); err == nil {
		t.Fatal("Non-core server accepted modification for a profile")
	}
	// Lookup through the verifier, requiring both signatures
	// It should never return ErrCouldntVerify because the verifier
	// should not switch to the new root without 2 signatures
	var lookupProfile *Profile
	for {
		lookupProfile, err = verifierClient.Lookup("bob")
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
		rqs[i] = &ClientMessage{ModifyProfile: NewSign(sk, MakeOperation(fmt.Sprint(i), profile)), InviteCode: testutil.MakeToken()}
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
