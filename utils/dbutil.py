# Copyright 2014 The Dename Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
from math import *
from message_pb2 import *
from google.protobuf import text_format
import plyvel


def pb2str(pb):
    return text_format.MessageToString(pb).decode('utf-8')
SignedServerMessage.__str__ = pb2str
SignedServerMessage.ServerMessage.__str__ = pb2str

def varint(*args):
    ret = bytes()
    for x in args:
        while x:
            ret += bytes([(x & 0x7f) | (int(x > 0x07f) << 7)])
            x >>= 7
    return ret

def unvarint(bs):
    ret = 0
    for byte in reversed(bs):
        ret <<= 7
        ret |= byte & (0x7f)
    return ret

db = plyvel.DB('../server/run')
# list(db.iterator(start=b'M'+varint(1,1), stop=b'M'+varint(1,2)))

ssm = lambda x: SignedServerMessage.FromString(x)
sm = lambda x: SignedServerMessage.ServerMessage.FromString(x)
def SSM(*args):
    return [ssm(v) for (k,v) in db.iterator(start=b'M'+varint(*args), stop=b'M'+varint(*(list(args[:-1])+[args[-1]+1])))]
def SM(*args):
    return [sm(ssm(v).Message) for (k,v) in db.iterator(start=b'M'+varint(*args), stop=b'M'+varint(*(list(args[:-1])+[args[-1]+1])))]
def O(round):
    return SignedServerMessage.ServerMessage.OperationsT.FromString(db.get(b'O'+varint(round)))
def Vround():
    return unvarint(db.get(b'Vround'))
