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
	"code.google.com/p/go.net/proxy"
	"encoding/base64"
	"fmt"
	. "github.com/andres-erbsen/dename/protocol"
	"github.com/gogo/protobuf/proto"
	"time"
)

type Verification struct {
	Verifier []string
}

type Freshness struct {
	Threshold        string
	NumConfirmations int
}

type Server struct {
	Timeout            string
	TransportPublicKey string
}

type Config struct {
	Verification Verification
	Freshness
	Update map[string]*Server
	Lookup map[string]*Server
}

func parseServer(address string, scfg *Server) (*server, error) {
	ret := &server{address: address}
	timeout := DefaultTimeout
	if scfg.Timeout != "" {
		timeout = scfg.Timeout
	}
	var err error
	ret.timeout, err = time.ParseDuration(timeout)
	if err != nil {
		return nil, err
	}
	transportPkData, err := base64.StdEncoding.DecodeString(scfg.TransportPublicKey)
	if err != nil {
		return nil, err
	}
	if len(transportPkData) != 32 {
		return nil, fmt.Errorf("malformed transport public key for server \"%s\" (expected %d bytes, got %d)", address, 32, len(transportPkData))
	}
	copy(ret.transportPK[:], transportPkData)
	return ret, nil
}

func parseServers(servers map[string]*Server) ([]*server, error) {
	ret := make([]*server, 0, len(servers))
	for a, s := range servers {
		u, err := parseServer(a, s)
		if err != nil {
			return nil, err
		}
		ret = append(ret, u)
	}
	return ret, nil
}

func NewClient(cfg *Config, dialer proxy.Dialer, now func() time.Time) (c *Client, err error) {
	if cfg == nil {
		cfg = &DefaultConfig
	}
	c = new(Client)
	c.freshnessThreshold, err = time.ParseDuration(cfg.Freshness.Threshold)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	c.now = now
	c.freshnessNumConfirmations = cfg.Freshness.NumConfirmations
	c.verifier = make(map[uint64]*Profile_PublicKey, len(cfg.Verification.Verifier))
	for _, pubkeyBase64 := range cfg.Verification.Verifier {
		pkData, err := base64.StdEncoding.DecodeString(pubkeyBase64)
		if err != nil {
			return nil, err
		}
		pk := new(Profile_PublicKey)
		if err = proto.Unmarshal(pkData, pk); err != nil {
			return nil, err
		}
		c.verifier[pk.ID()] = pk
	}

	if c.update, err = parseServers(cfg.Update); err != nil {
		return nil, err
	}
	if c.lookup, err = parseServers(cfg.Lookup); err != nil {
		return nil, err
	}

	c.consensusNumConfirmations = len(cfg.Verification.Verifier)
	if dialer == nil {
		dialer = DefaultDialer
	}
	c.dialer = dialer
	return c, nil
}
