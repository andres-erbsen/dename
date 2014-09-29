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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	. "github.com/andres-erbsen/dename/protocol"
	"github.com/syndtr/goleveldb/leveldb"
	leveldbopt "github.com/syndtr/goleveldb/leveldb/opt"
)

var _ = fmt.Printf

const (
	HASH_BYTES = 32
	HASH_BITS  = HASH_BYTES * 8
	DB_PREFIX  = 'T'
)

func b2i(b bool) int {
	if b {
		return 1
	} else {
		return 0
	}
}

func concatBits(boolSlices ...[]bool) (ret []bool) {
	for _, boolSlice := range boolSlices {
		ret = append(ret, boolSlice...)
	}
	return
}

func toBits(num int, bs []byte) []bool {
	bits := make([]bool, num)
	for i := 0; i < len(bits); i++ {
		bits[i] = (bs[i/8]<<uint(i%8))&(1<<7) > 0
	}
	return bits
}

func toBytes(bits []bool) []byte {
	bs := make([]byte, (len(bits)+7)/8)
	for i := 0; i < len(bits); i++ {
		if bits[i] {
			bs[i/8] |= (1 << 7) >> uint(i%8)
		}
	}
	return bs
}

type mmDB interface { // *leveldb.DB or *leveldb.Snapshot
	Get([]byte, *leveldbopt.ReadOptions) ([]byte, error)
}

type MerkleMap struct {
	root         *node
	dontHashKeys bool // to disable key hashing for testing
	db           mmDB
}

type diskNode struct {
	substring []bool
	hash      [HASH_BYTES]byte
	value     []byte
}

type node struct {
	diskNode
	tree      *MerkleMap
	parent    *node
	key       []bool
	children  [2]*node
	needsPut  bool
	needsHash bool
}

func OpenMerkleMap(db mmDB) *MerkleMap {
	m := &MerkleMap{db: db}
	m.root = m.loadNode([]bool{})
	return m
}

func (m *MerkleMap) GetRootHash() []byte {
	if m.root == nil {
		return make([]byte, HASH_BYTES)
	} else {
		return m.root.Hash()
	}
}

func (m *MerkleMap) Lookup(key []byte) (value []byte, proof []*ClientReply_MerklemapNode) {
	keyHash := sha256.Sum256(key)
	if m.dontHashKeys && len(key) == HASH_BYTES {
		copy(keyHash[:], key)
	}
	keyBits := toBits(HASH_BITS, keyHash[:])
	n := m.root
	if n == nil {
		return nil, nil
	}
	for {
		l := uint64(((len(n.substring) - 1) % 8) + 1)
		wireNode := &ClientReply_MerklemapNode{
			SubstringBitsInLastByte: &l,
			Substring:               toBytes(n.substring),
			Value:                   n.value,
		}
		proof = append(proof, wireNode)
		for i := 0; i < len(n.substring); i++ {
			if n.substring[i] != keyBits[len(n.key)+i] {
				return
			}
		}
		if len(n.key)+len(n.substring) == HASH_BITS {
			return n.value, proof
		}
		descendingRight := keyBits[len(n.key)+len(n.substring)]
		if descendingRight && n.getChild(false) != nil {
			wireNode.LeftChildHash = n.getChild(false).Hash()
		} else if !descendingRight && n.getChild(true) != nil {
			wireNode.RightChildHash = n.getChild(true).Hash()
		}
		n = n.getChild(descendingRight)
	}
}

func (m *MerkleMap) Set(key []byte, val []byte) {
	value := make([]byte, len(val))
	copy(value, val)
	keyHash := sha256.Sum256(key)
	if m.dontHashKeys && len(key) == HASH_BYTES {
		copy(keyHash[:], key)
	}
	keyBits := toBits(HASH_BITS, keyHash[:])
	n := m.root
	if n == nil {
		m.root = &node{
			diskNode: diskNode{
				substring: keyBits,
				value:     value,
			},
			tree:      m,
			key:       []bool{},
			needsPut:  true,
			needsHash: true,
		}
		return
	}
outer:
	for {
		for i := 0; i < len(n.substring); i++ {
			if n.substring[i] != keyBits[len(n.key)+i] {
				// split
				oldChild := &node{
					diskNode: diskNode{
						substring: n.substring[i+1:],
						value:     n.value,
					},
					tree:      n.tree,
					parent:    n,
					key:       concatBits(n.key, n.substring[:i+1]),
					children:  n.children,
					needsPut:  true,
					needsHash: true,
				}
				newChild := &node{
					diskNode: diskNode{
						substring: keyBits[len(n.key)+i+1:],
						value:     value,
					},
					tree:     n.tree,
					parent:   n,
					key:      keyBits[:len(n.key)+i+1],
					needsPut: true,
				}
				for i := 0; i < 2; i++ {
					if n.children[i] != nil {
						n.children[i].parent = oldChild
					}
				}
				n.children[b2i(n.substring[i])] = oldChild
				n.children[b2i(!n.substring[i])] = newChild
				n.value = nil
				n.substring = n.substring[:i]
				n = newChild
				break outer
			}
		}
		if len(n.key)+len(n.substring) == HASH_BITS {
			// leaf. the key is already present, replace the value
			n.value = value
			break
		}
		n = n.getChild(keyBits[len(n.key)+len(n.substring)])
	}
	// At this point, n is whatever leaf needs to be propagated up from
	for ; n != nil; n = n.parent {
		n.needsHash = true
		n.needsPut = true
	}
}

func (m *MerkleMap) Flush(wb *leveldb.Batch) {
	m.root.flush(wb)
}

func (n *node) flush(wb *leveldb.Batch) {
	if n != nil && n.needsPut {
		n.store(wb)
		n.children[0].flush(wb)
		n.children[1].flush(wb)
		n.needsPut = false
	}
}

func (n *node) getChild(isRight bool) *node {
	if n.children[b2i(isRight)] != nil {
		if n.children[b2i(isRight)].parent != n {
			panic("oh dear")
		}
		return n.children[b2i(isRight)]
	}
	childKey := concatBits(n.key, n.substring, []bool{isRight})
	child := n.tree.loadNode(childKey)
	if child == nil {
		return nil
	}
	child.parent = n
	n.children[b2i(isRight)] = child
	return child
}

func (m *MerkleMap) loadNode(key []bool) *node {
	valueBytes, err := m.db.Get(serializeKey(key), nil)
	if err != nil && err != leveldb.ErrNotFound {
		panic(err)
	} else if err == leveldb.ErrNotFound {
		return nil
	}
	n := &node{
		diskNode: deserializeNode(valueBytes),
		tree:     m,
		key:      key,
	}
	return n
}

func (n *node) store(wb *leveldb.Batch) {
	wb.Put(serializeKey(n.key), n.serialize())
}

func serializeKey(key []bool) []byte {
	return append(append([]byte{DB_PREFIX}, toBytes(key)...), byte((len(key)-1)%8+1))
}

func deserializeNode(buf []byte) (n diskNode) {
	substringLen := int(binary.LittleEndian.Uint16(buf[:2]))
	n.substring = toBits(substringLen, buf[2:2+HASH_BYTES])
	copy(n.hash[:], buf[2+HASH_BYTES:2+HASH_BYTES+HASH_BYTES])
	n.value = append(n.value, buf[2+HASH_BYTES+HASH_BYTES:]...)
	return
}

func (n *node) serialize() []byte {
	buf := make([]byte, 2+HASH_BYTES+HASH_BYTES+len(n.value))
	binary.LittleEndian.PutUint16(buf, uint16(len(n.substring)))
	copy(buf[2:2+HASH_BYTES], toBytes(n.substring))
	copy(buf[2+HASH_BYTES:2+HASH_BYTES+HASH_BYTES], n.Hash())
	copy(buf[2+HASH_BYTES+HASH_BYTES:], n.value)
	return buf
}

func (n *node) Hash() []byte {
	if n.needsHash {
		hash := sha256.New()
		hash.Write([]byte{byte((len(n.substring) + 7) / 8), byte((len(n.substring)-1)%8 + 1)})
		hash.Write(toBytes(n.substring))
		if n.getChild(false) != nil {
			hash.Write(n.getChild(false).Hash())
		} else {
			hash.Write(make([]byte, HASH_BYTES))
		}
		if n.getChild(true) != nil {
			hash.Write(n.getChild(true).Hash())
		} else {
			hash.Write(make([]byte, HASH_BYTES))
		}
		hash.Write(n.value)
		copy(n.hash[:], hash.Sum(nil))
		n.needsHash = false
	}
	return n.hash[:]
}
