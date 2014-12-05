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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/agl/ed25519"
	. "github.com/andres-erbsen/dename/protocol"
	"github.com/gogo/protobuf/proto"
	"github.com/syndtr/goleveldb/leveldb"
	"log"
	"math/rand"
	"os"
	"sort"
	"sync"
	"time"
)

var _ = fmt.Printf

type serverState struct {
	sync.RWMutex
	round         uint64
	confirmations []*Message
	snapshot      *leveldb.Snapshot
	merklemap     *MerkleMap
}

type server struct {
	id            uint64
	sk            *[ed25519.PrivateKeySize]byte
	db            *leveldb.DB
	coreServerIDs []uint64 // sorted

	stop         chan struct{}
	waitStop     sync.WaitGroup
	communicator *communicator
	frontend     *frontend

	state                  serverState
	reconfirmationTimer    *time.Timer
	reconfirmationTimerMu  sync.Mutex
	reconfirmationInterval time.Duration
}

func OpenServer(dbpath string, sk *[ed25519.PrivateKeySize]byte,
	communicator *communicator, frontend *frontend) (*server, error) {
	ret := &server{sk: sk, communicator: communicator, frontend: frontend,
		stop: make(chan struct{}), db: openDB(dbpath)}
	server := ret
	frontend.server = server
	communicator.recallMessage = server.RecallMessage
	server.id = (&Profile_PublicKey{Ed25519: sk[32:]}).ID()
	communicator.id = server.id

	server.coreServerIDs = make([]uint64, 0, len(communicator.servers))
	for id, s := range communicator.servers {
		if s.IsCore {
			server.coreServerIDs = append(server.coreServerIDs, id)
		}
	}
	sort.Sort(uint64s(server.coreServerIDs))
	return server, server.loadState()
}

func (server *server) loadState() (err error) {
	server.state.snapshot, err = server.db.GetSnapshot()
	if err != nil {
		panic(err)
	}
	server.state.merklemap = OpenMerkleMap(server.state.snapshot)
	server.state.confirmations = make([]*Message, 0, len(server.coreServerIDs))
	server.state.round = server.GetRoundNumber() - 1
	server.reconfirmationTimer = time.NewTimer(server.reconfirmationInterval)
	server.reconfirmationInterval = 2 * time.Second
	if server.state.round < 1 {
		return nil
	}
	for _, id := range server.coreServerIDs {
		msg := new(Message)
		msg.SignedServerMessage = server.RecallMessage(server.state.round, PHASE_HASH_STATE, id)
		MustUnmarshal(msg.SignedServerMessage.Message, &msg.SignedServerMessage_ServerMessage)
		server.state.confirmations = append(server.state.confirmations, msg)
	}
	return nil
}

func (server *server) Shutdown() (err error) {
	close(server.stop)
	server.waitStop.Wait()
	return server.db.Close()
}

func (server *server) Publish(wb *leveldb.Batch, msg *Message) {
	msg.Server = &server.id
	msg.Time = new(uint64)
	*msg.Time = uint64(time.Now().Unix())
	msg.SignedServerMessage = nil
	msgdata := PBEncode(&msg.SignedServerMessage_ServerMessage)
	sig := ed25519.Sign(server.sk, append([]byte("msg\x00"), msgdata...))
	msg.SignedServerMessage = &SignedServerMessage{Message: msgdata, Signature: sig[:]}
	bmsg := &BackendMessage{SignedServerMessage: msg.SignedServerMessage}
	if wb != nil {
		putMsg(wb, msg)
		if err := server.db.Write(wb, WO_sync); err != nil {
			panic(err)
		}
		wb.Reset()
	} else {
		if err := server.db.Write(putMsg(new(leveldb.Batch), msg), nil); err != nil {
			panic(err)
		}
	}
	server.communicator.Broadcast(bmsg)
}

func (server *server) Run() {
	defer server.waitStop.Done()
	server.waitStop.Add(1)
	go server.ReconfirmPeriodically()
	justStarted := true
	cooldown := time.NewTimer(0)
	roundNumber := server.GetRoundNumber()
	server.StartCollectingReconfirmations(roundNumber - 1)
	for ; ; roundNumber++ {
		if !justStarted {
			select {
			case <-server.stop:
				return
			case <-cooldown.C:
			}
			select {
			case <-server.stop:
				return
			case <-server.frontend.hasOperations:
			case <-server.communicator.NotifyAny(roundNumber, PHASE_HASH_OPS):
			}
		}
		justStarted = false
		cooldown.Reset(0)

		profileOperations, operationsTime, wb, err := server.PrepareOperations(roundNumber, server.frontend.GetOperations)
		if err == errStop {
			return
		} else if err != nil {
			panic(err)
		}

		syncedOps := make(chan struct{})
		go func() {
			if err := server.db.Write(wb, WO_sync); err != nil {
				panic(err)
			}
			wb.Reset()
			close(syncedOps)
		}()
		merklemap := OpenMerkleMap(server.db)
		for _, op := range profileOperations {
			name, profileData, err := validateOperation(merklemap, op, operationsTime)
			// log.Printf("server %x round %d operation %d name \"%s\": %v", server.id, roundNumber, i, name, err)
			if err != nil {
				continue
			}
			merklemap.Set(name, profileData)
		}
		<-syncedOps

		err = server.FinalizeRound(roundNumber, merklemap, wb)
		if err == errStop {
			return
		} else if err != nil {
			panic(err)
		}
		server.frontend.DoneWith(profileOperations)
		// fmt.Printf("%x # %d operations (%d) time %v state %x\n", server.id, roundNumber, len(profileOperations), time.Unix(int64(operationsTime), 0), merklemap.GetRootHash())
	}
}

func (server *server) GetRoundNumber() uint64 {
	roundNumberUvarint, err := server.db.Get([]byte("Vround"), nil)
	if err != nil && err != leveldb.ErrNotFound {
		panic(err)
	} else if err == leveldb.ErrNotFound {
		return 1
	}
	roundNumber, err := binary.ReadUvarint(bytes.NewReader(roundNumberUvarint))
	if err != nil {
		panic(err)
	}
	return roundNumber
}

func (server *server) CommitToOperations(roundNumber uint64,
	getOperations func() *SignedServerMessage_ServerMessage_OperationsT) ([]byte, *Message) {
	ourOperations, err := server.db.Get(dbKey('O', roundNumber), nil)
	if err != nil && err != leveldb.ErrNotFound {
		panic(err)
	}

	wb := new(leveldb.Batch)
	if err == leveldb.ErrNotFound {
		ourOperations = PBEncode(getOperations())
		wb.Put(dbKey('O', roundNumber), ourOperations)
	}

	ourMsgHashOps := new(Message)
	opsHash := sha256.Sum256(ourOperations)
	ourMsgHashOps.HashOfOperations = opsHash[:]
	ourMsgHashOps.Round = &roundNumber
	server.Publish(wb, ourMsgHashOps)
	return ourOperations, ourMsgHashOps
}

func (server *server) PrepareOperations(roundNumber uint64, getOperations func() *SignedServerMessage_ServerMessage_OperationsT) ([]*SignedProfileOperation /*time*/, uint64, *leveldb.Batch, error) {
	ourOperations, ourMsgHashOps := server.CommitToOperations(roundNumber, getOperations)
	reminder := ourMsgHashOps.SignedServerMessage
	if !server.communicator.servers[server.id].IsCore {
		reminder = nil
	}
	hashOfOperationsMsgs, err := server.communicator.CollectFromEach(roundNumber, PHASE_HASH_OPS, reminder)
	if err != nil {
		return nil, 0, nil, err
	}
	wb := batchMsgs(nil, flattenMsgs(hashOfOperationsMsgs))
	h := sha256.New()
	for _, id := range server.coreServerIDs {
		h.Write(hashOfOperationsMsgs[id].HashOfOperations)
	}
	ourMsgHashHashes := new(Message)
	ourMsgHashHashes.HashOfHashes = h.Sum(nil)
	ourMsgHashHashes.Round = &roundNumber
	server.Publish(wb, ourMsgHashHashes)

	hashOfHashesMsgs, err := server.communicator.CollectGloballyConsistent(roundNumber, PHASE_HASH_HASHES, msgHashOfHashes_s)
	if err != nil {
		return nil, 0, nil, err
	}
	wb = batchMsgs(wb, flattenMsgs(hashOfHashesMsgs))

	ourOperationsMsg := new(Message)
	ourOperationsMsg.Operations = ourOperations
	ourOperationsMsg.Round = &roundNumber
	server.Publish(nil, ourOperationsMsg)

	operationsMsgs, err := server.communicator.CollectFromEach(roundNumber, PHASE_OPS, nil)
	if err != nil {
		return nil, 0, nil, err
	}
	for id, msg := range operationsMsgs {
		realHash := sha256.Sum256(msg.Operations)
		reportedHash := hashOfOperationsMsgs[id].HashOfOperations
		if !bytes.Equal(realHash[:], reportedHash) {
			log.Fatalf("%x published operations that did not match hash: h(%#v) != %#v", id, msg.Operations, reportedHash)
		}
	}

	wb = batchMsgs(wb, flattenMsgs(operationsMsgs))
	operations := make(map[uint64]*SignedServerMessage_ServerMessage_OperationsT)
	seedHasher := sha256.New()
	operationsTime := uint64(1<<64 - 1)
	for id, msg := range operationsMsgs {
		operations[id] = new(SignedServerMessage_ServerMessage_OperationsT)
		err = proto.Unmarshal(msg.Operations, operations[id])
		if err != nil {
			log.Fatalf("Failed to decode Operations from %x: %x", id, msg.Operations)
		}
		seedHasher.Write(operations[id].Seed)
		if operationsTime > *operations[id].Time {
			operationsTime = *operations[id].Time
		}
	}

	var orderedOperations []*SignedProfileOperation
	for _, i := range rand.New(&denamePrng{h: seedHasher}).Perm(len(server.coreServerIDs)) {
		orderedOperations = append(orderedOperations, operations[server.coreServerIDs[i]].ProfileOperations...)
	}

	return orderedOperations, operationsTime, wb, nil
}

func (server *server) FinalizeRound(roundNumber uint64, merklemap *MerkleMap, wb *leveldb.Batch) error {
	ourMsgHashOfState := new(Message)
	ourMsgHashOfState.HashOfState = merklemap.GetRootHash()
	ourMsgHashOfState.Round = &roundNumber
	server.Publish(nil, ourMsgHashOfState)

	server.reconfirmationTimerMu.Lock()
	server.reconfirmationTimer.Reset(server.reconfirmationInterval)
	server.reconfirmationTimerMu.Unlock()

	roundNumberBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(roundNumberBuf, roundNumber+1)
	wb.Put([]byte("Vround"), roundNumberBuf[:n])
	merklemap.Flush(wb)

	hashOfStateMsgs, err := server.communicator.CollectGloballyConsistent(
		roundNumber, PHASE_HASH_STATE, msgHashOfState_s)
	if err != nil {
		return err
	}
	hashOfStateMsgsFlat := flattenMsgs(hashOfStateMsgs)
	wb = batchMsgs(wb, hashOfStateMsgsFlat)
	if err = server.db.Write(wb, WO_sync); err != nil {
		panic(err)
	}

	server.state.Lock()
	server.state.confirmations = hashOfStateMsgsFlat
	server.state.round = roundNumber
	server.state.snapshot.Release()
	if server.state.snapshot, err = server.db.GetSnapshot(); err != nil {
		panic(err)
	}
	merklemap.db = server.state.snapshot
	server.state.merklemap = merklemap
	server.state.Unlock()
	server.StartCollectingReconfirmations(roundNumber)
	return nil
}

func (server *server) StartCollectingReconfirmations(round uint64) {
	server.communicator.StartWaitingFor(func(msg *Message) (exit bool, consumeMessage bool) {
		server.state.RLock()
		currentFinalizedRound := server.state.round
		server.state.RUnlock()
		if round < currentFinalizedRound {
			return true, false
		}
		if *msg.Round > round {
			return false, false
		}
		exit, consumeMessage = false, true
		if *msg.Round < round { // too old to be interesting
			return
		}
		if msg.Phase() != PHASE_HASH_STATE {
			return
		}
		server.state.Lock()
		defer server.state.Unlock()
		if round < server.state.round {
			return true, false
		}
		replaced := false
		for i, alreadyMsg := range server.state.confirmations {
			if *msg.Server != *alreadyMsg.Server {
				continue
			}
			if !bytes.Equal(msg.HashOfState, alreadyMsg.HashOfState) {
				log.Printf("Server %x signed two different states for round %d; messages %v and %v\n(%x != %x)", *msg.Server, *msg.Round, *alreadyMsg, *msg, alreadyMsg.HashOfState, msg.HashOfState)
				if s, ok := server.communicator.servers[*msg.Server]; ok && s.IsCore {
					os.Exit(1)
				} else {
					return
				}
			}
			if *msg.Time <= *alreadyMsg.Time {
				return
			}
			server.state.confirmations[i] = msg
			replaced = true
		}
		if !replaced {
			server.state.confirmations = append(server.state.confirmations, msg)
		}
		// log.Printf("%x added reconfirmation from %x round %d", server.id, *msg.Server, *msg.Round)
		if err := server.db.Write(putMsg(new(leveldb.Batch), msg), nil); err != nil {
			panic(err)
		}
		return
	})
}

func (server *server) ReconfirmPeriodically() {
	defer server.waitStop.Done()
	for {
		select {
		case <-server.stop:
			return
		case <-server.reconfirmationTimer.C:
			server.state.Lock()
			for _, msg := range server.state.confirmations {
				if *msg.Server != server.id {
					continue
				}
				server.Publish(new(leveldb.Batch), msg) // modifies time and signature, saves to db
			}
			server.state.Unlock()
			server.reconfirmationTimerMu.Lock()
			server.reconfirmationTimer.Reset(server.reconfirmationInterval)
			server.reconfirmationTimerMu.Unlock()
		}
	}
}

func (server *server) RecallMessage(round, phase, serverID uint64) *SignedServerMessage {
	smsg := new(SignedServerMessage)
	msgData, err := server.db.Get(dbKey('M', round, phase, serverID), nil)
	if err == leveldb.ErrNotFound {
		return nil
	} else if err != nil {
		panic(err)
	}
	MustUnmarshal(msgData, smsg)
	return smsg
}

type uint64s []uint64

func (s uint64s) Len() int           { return len(s) }
func (s uint64s) Less(i, j int) bool { return s[i] < s[j] }
func (s uint64s) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
