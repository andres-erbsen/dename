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
	"fmt"
	"github.com/syndtr/goleveldb/leveldb"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/andres-erbsen/dename/client"
)

var dbg = 0

func TestOneEntry(t *testing.T) {
	dir, err := ioutil.TempDir("", "merklemap")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	m := OpenMerkleMap(db)
	m.dontHashKeys = true
	key := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	val := []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
	m.Set(key, val)
	wb := new(leveldb.Batch)
	m.Flush(wb)
	err = db.Write(wb, nil)
	if err != nil {
		panic(err)
	}
	v, proof := m.Lookup(key)
	if !bytes.Equal(v, val) {
		panic(fmt.Errorf("Value mismatch: %x / %x", v, val))
	}
	_, err = client.VerifyResolveAgainstRoot(m.GetRootHash(), key, proof, t)
	if err != nil {
		panic(err)
	}
}

func TestTwoEntries(t *testing.T) {
	dir, err := ioutil.TempDir("", "merklemap")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	m := OpenMerkleMap(db)
	m.dontHashKeys = true
	m.dontHashKeys = true
	key := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	val := []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
	m.Set(key, val)
	wb := new(leveldb.Batch)
	m.Flush(wb)
	err = db.Write(wb, nil)
	if err != nil {
		panic(err)
	}
	key[15]++
	val[15]++
	m.Set(key, val)
	wb = new(leveldb.Batch)
	m.Flush(wb)
	err = db.Write(wb, nil)
	if err != nil {
		panic(err)
	}
	for i := 0; i < 2; i++ {
		if dbg > 0 {
			fmt.Printf("Lookup %d:\n", i)
		}
		_, proof := m.Lookup(key)
		_, err = client.VerifyResolveAgainstRoot(m.GetRootHash(), key, proof, t)
		if err != nil {
			panic(err)
		}
		key[15]--
	}
}

//
//func TestFinalBitsDifferentOK(t *testing.T) {
//	options := leveldb.NewOptions()
//	options.SetCreateIfMissing(true)
//	db, err := leveldb.Open("tree.dat", options)
//	if err != nil {
//		panic(err)
//	}
//	key := []byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
//	val := []byte{31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
//	wb := new(leveldb.Batch)
//	err = Set(db, wb, key, val)
//	if err != nil {
//		panic(err)
//	}
//	err = db.Write(WO, wb)
//	if err != nil {
//		panic(err)
//	}
//	key[31]++; val[31]++;
//	wb.Close()
//	wb = new(leveldb.Batch)
//	err = Set(db, wb, key, val)
//	if err != nil {
//		panic(err)
//	}
//	err = db.Write(WO, wb)
//	if err != nil {
//		panic(err)
//	}
//	key[30]++; val[30]++;
//	wb.Close()
//	wb = new(leveldb.Batch)
//	err = Set(db, wb, key, val)
//	if err != nil {
//		panic(err)
//	}
//	err = db.Write(WO, wb)
//	if err != nil {
//		panic(err)
//	}
//	wb.Close()
//	key[30]--; val[30]--;
//	_, path, err := GetPath(db, key)
//	if err != nil {
//		panic(err)
//	}
//	rootHash, err := GetRootHash(db)
//	if err != nil {
//		panic(err)
//	}
//	if !bytes.Equal(rootHash[:], path.ComputeRootHash(key, val)) {
//		panic("Root hash mismatch!")
//	}
//}
//
func TestRandomly(t *testing.T) {
	bestTime := 100000
	bestSeed := -1
	var testCount int
	if testing.Short() {
		testCount = 0x10
	} else {
		testCount = 0x100
	}
	dir, err := ioutil.TempDir("", "merklemap")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	for i := 0x0; i < testCount; i++ {
		rand.Seed(int64(0x1234567 + (i ^ (i << 3)) + i*100000007))
		db, err := leveldb.OpenFile(filepath.Join(dir, fmt.Sprint(i)), nil)
		if err != nil {
			panic(err)
		}
		randSign := rand.Intn(2)*2 - 1
		big := rand.Intn(20) == 0
		var itCount int
		if big {
			itCount = 10000
		} else {
			itCount = 100
		}
		time := mapTest(db, itCount, (1+rand.Intn(256))*randSign, 3)
		if testing.Verbose() {
			fmt.Printf("seed %x: %v\n", i, time)
		}
		if time < bestTime {
			bestTime = time
			bestSeed = i
		}
		db.Close()
	}
	if testing.Verbose() {
		fmt.Printf("SEED %x: %v\n", bestSeed, bestTime)
	}
}

func BenchmarkBigTree(b *testing.B) {
	rand.Seed(0x7777)
	dir, err := ioutil.TempDir("", "merklemap")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	var iters int
	// TODO proper use of b.N
	if testing.Short() {
		iters = 50000
	} else {
		iters = 1000000
	}
	mapTest(db, iters, 256, 2)
}

func mapTest(db *leveldb.DB, itCount int, byteRange int, opn int) int {
	m := OpenMerkleMap(db)
	m.dontHashKeys = true
	bytez := func(b byte) [32]byte {
		var bytes [32]byte
		for i := range bytes {
			bytes[i] = b<<4 | b
		}
		return bytes
	}
	randBytes := func() []byte {
		var bs [32]byte
		if byteRange < 0 {
			bs = bytez(byte(rand.Intn(-byteRange)))
			bs[0] = byte(rand.Intn(-byteRange))
			bs[31] = byte(rand.Intn(-byteRange))
			return bs[:]
		} else {
			for i := range bs {
				bs[i] = byte(rand.Intn(byteRange))
			}
			if dbg > 2 {
				fmt.Printf("rand bytes = %x\n", bs)
			}
			return bs[:]
		}
	}
	refMap := map[[32]byte][]byte{}
	refMapKeys := [][]byte{}
	randMapKey := func() []byte {
		return refMapKeys[rand.Intn(len(refMapKeys))]
	}
	refSet := func(key []byte, val []byte) {
		var k [32]byte
		copy(k[:], key)
		if _, present := refMap[k]; !present {
			refMapKeys = append(refMapKeys, key)
		}
		refMap[k] = val
	}
	refGet := func(key []byte) []byte {
		var k [32]byte
		copy(k[:], key)
		return refMap[k]
	}
	treeSet := func(key []byte, val []byte) {
		if dbg > 1 {
			fmt.Fprintf(os.Stdout, "set: [%x] = %x...\n", key, val)
		}
		m.Set(key, val)
		if dbg > 0 {
			fmt.Fprintf(os.Stdout, "set  [%x] = %x done\n", key, val)
		}
	}
	treeGet := func(key []byte) []byte {
		if dbg > 2 {
			fmt.Fprintf(os.Stdout, "read [%x]...\n", key)
		}
		val, proof := m.Lookup(key)
		if val != nil {
			_, err := client.VerifyResolveAgainstRoot(m.GetRootHash(), key, proof /*testing*/, true)
			if err != nil {
				panic(err)
			}
		}
		if dbg > 1 {
			fmt.Fprintf(os.Stdout, "read [%x] = %x\n", key, val)
		}
		return val
	}
	for i := 0; i < itCount; i++ {
		if i%1000 == 0 && testing.Verbose() {
			fmt.Printf("operation %v\n", i)
		}
		switch rand.Intn(opn) {
		case 0:
			k := randBytes()
			v := randBytes()
			refSet(k, v)
			treeSet(k, v)
		case 1:
			k := randBytes()
			v1 := refGet(k)
			v2 := treeGet(k)
			if dbg > 0 {
				fmt.Printf("1: [%x] = %x, %x\n", k, v2, v1)
			}
			if !bytes.Equal(v1, v2) {
				panic("wrong 1")
			}
		case 2:
			if len(refMap) > 0 {
				k := randMapKey()
				v1 := refGet(k)
				if dbg > 1 {
					fmt.Printf("read [%x]\n", k)
				}
				v2 := treeGet(k)
				if dbg > 0 {
					fmt.Printf("2: [%x] = %x, %x\n", k, v2, v1)
				}
				if !bytes.Equal(v1, v2) {
					panic(fmt.Sprintf("wrong 2 (%x!=%x)", v1, v2))
				}
			}
		}
		if rand.Intn(10) == 0 {
			wb := new(leveldb.Batch)
			m.Flush(wb)
			var err error
			// TODO sync in sensible intervals
			if rand.Intn(100) == 0 {
				err = db.Write(wb, WO_sync)
			} else {
				err = db.Write(wb, nil)
			}
			if err != nil {
				panic(err)
			}
			if rand.Intn(5) == 0 {
				m = OpenMerkleMap(db)
				m.dontHashKeys = true
			}
		}
	}
	return 100000000
}
