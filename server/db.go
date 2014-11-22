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
	. "github.com/andres-erbsen/dename/protocol"
	"encoding/binary"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

var WO_sync = &opt.WriteOptions{Sync: true}

func openDB(path string) *leveldb.DB {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		panic(err)
	}
	return db
}

func dbKey(prefix byte, fields ...uint64) []byte {
	buf := make([]byte, 1+len(fields)*binary.MaxVarintLen64)
	buf[0] = prefix
	bytesWritten := 1
	for _, value := range fields {
		bytesWritten += binary.PutUvarint(buf[bytesWritten:], value)
	}
	return buf[:bytesWritten]
}

func putMsg(wb *leveldb.Batch, msg *Message) *leveldb.Batch {
	wb.Put(dbKey('M', *msg.Round, uint64(msg.Phase()), *msg.Server), PBEncode(msg.SignedServerMessage))
	return wb
}

func flattenMsgs(msgmap map[uint64]*Message) (ret []*Message) {
	ret = make([]*Message, 0, len(msgmap))
	for _, msg := range msgmap {
		ret = append(ret, msg)
	}
	return ret
}

func batchMsgs(wb *leveldb.Batch, msgs []*Message) *leveldb.Batch {
	if wb == nil {
		wb = new(leveldb.Batch)
	}
	for _, msg := range msgs {
		putMsg(wb, msg)
	}
	return wb
}
