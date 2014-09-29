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


package client

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	. "github.com/andres-erbsen/dename/protocol"
)

const hASH_BYTES = 32

// VerifyResolveAgainstRoot decodes a profile from a resolve structure and
// verifies that it is indeed a part of a mrklemap with rootHash.  resolve
// contains nodes of a binary trie, except that each pointer has been replaced
// with a cryptographic hash of its target. As a binary trie lookup only uses
// nodes on one branch of the tree, all other nodes are omitted. Furthermore,
// hashes of nodes that /are/ present are implicit: if a node's child hash is
// nil, we can find it by hashing the next given node. This function assumes
// that the hash of the root has been authenticated externally and verifies that
// 1) all provided nodes indeed lie in their claimed positions in the trie by
// recomputing the hash of the root from the provided nodes and 2) that the
// parts of the trie contained in resolve unambiguously determine the result of
// the lookup of name by running the binary trie tree lookup algorithm on these
// nodes.
func VerifyResolveAgainstRoot(rootHash, name []byte, resolve []*ClientReply_MerklemapNode, testing ...interface{}) (
	profile []byte, err error) {
	if !bytes.Equal(reproduceRootHash(resolve), rootHash) {
		return nil, fmt.Errorf("root hash does not match")
	}
	nameHash := sha256.Sum256(name)
	if len(testing) > 0 {
		copy(nameHash[:], name)
	}
	var requiredPath [hASH_BYTES * 8]bool
	for i := range requiredPath {
		requiredPath[i] = nameHash[i/8]&(0x80>>uint(i%8)) != 0
	}
	return reproduceBinaryTrieLookup(resolve, requiredPath[:])
}

func reproduceRootHash(resolve []*ClientReply_MerklemapNode) []byte {
	if len(resolve) == 0 {
		return nil
	}
	curHash := hashWireNode(resolve[len(resolve)-1], [hASH_BYTES]byte{}, [hASH_BYTES]byte{})
	for i := len(resolve) - 2; i >= 0; i-- {
		hasLeft, hasRight := resolve[i].LeftChildHash != nil, resolve[i].RightChildHash != nil
		hasValue := resolve[i].Value != nil
		var substituteLeftHash, substituteRightHash [hASH_BYTES]byte
		switch {
		case !hasLeft && hasRight && !hasValue:
			substituteLeftHash = curHash
		case hasLeft && !hasRight && !hasValue:
			substituteRightHash = curHash
		default:
			return nil
		}
		curHash = hashWireNode(resolve[i], substituteLeftHash, substituteRightHash)
	}
	return curHash[:]
}

func reproduceBinaryTrieLookup(resolve []*ClientReply_MerklemapNode, remainingPath []bool) ([]byte, error) {
	for _, node := range resolve {
		if *node.SubstringBitsInLastByte > 8 {
			return nil, fmt.Errorf("invalid node: bitsInLastByte: %d", *node.SubstringBitsInLastByte)
		}
		for i := 0; i < len(node.Substring)*8-8+int(*node.SubstringBitsInLastByte); i++ {
			if len(remainingPath) == 0 {
				return nil, fmt.Errorf("merklemap path too long")
			}
			var requiredBit bool
			requiredBit, remainingPath = remainingPath[0], remainingPath[1:]
			observedBit := node.Substring[i/8]&(0x80>>uint(i%8)) != 0
			if observedBit != requiredBit {
				return nil, nil // the required path is not present in the merklemap
			}
		}
		if node.Value == nil {
			if node.LeftChildHash != nil && node.RightChildHash != nil {
				return nil, fmt.Errorf("merklemap node with both children given")
			}
			if node.LeftChildHash == nil && node.RightChildHash == nil {
				return nil, fmt.Errorf("merklemap node with no children given")
			}
			descendingRight := node.RightChildHash == nil
			if descendingRight != remainingPath[0] {
				return nil, fmt.Errorf("merklemap wrong branch taken")
			}
			remainingPath = remainingPath[1:]
		} else {
			if len(remainingPath) > 0 {
				return nil, fmt.Errorf("merklemap: value too high in the tree")
			}
			return node.Value, nil
		}
	}
	return nil, fmt.Errorf("merklemap: no value or contradiction given")
}

func hashWireNode(wireNode *ClientReply_MerklemapNode, substituteLeftHash,
	substituteRightHash [hASH_BYTES]byte) [hASH_BYTES]byte {
	hash := sha256.New()
	hash.Write([]byte{byte(len(wireNode.Substring)), byte(*wireNode.SubstringBitsInLastByte)})
	hash.Write(wireNode.Substring)
	if wireNode.LeftChildHash != nil {
		hash.Write(wireNode.LeftChildHash)
	} else {
		hash.Write(substituteLeftHash[:])
	}
	if wireNode.RightChildHash != nil {
		hash.Write(wireNode.RightChildHash)
	} else {
		hash.Write(substituteRightHash[:])
	}
	hash.Write(wireNode.Value)
	var ret [hASH_BYTES]byte
	hash.Sum(ret[:0])
	return ret
}
