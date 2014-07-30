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
	"encoding/binary"
	"hash"
)

type denamePrng struct {
	h   hash.Hash // assumed to have 32-byte output and be copyable
	i   uint64    // output block number
	out bytes.Buffer
}

func (s *denamePrng) Int63() (ret int64) {
	if s.out.Len() == 0 {
		s.out.Reset()
		h := s.h // copy
		binary.Write(h, binary.LittleEndian, s.i)
		s.i++
		s.out.Write(h.Sum(nil))
	}
	binary.Read(&s.out, binary.LittleEndian, &ret)
	return ret & 0x7fffffffffffffff
}

func (*denamePrng) Seed(int64) { panic("denamePrng.Seed") }
