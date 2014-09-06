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
	"code.google.com/p/goprotobuf/proto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	. "github.com/andres-erbsen/dename/protocol"
	"io/ioutil"
	"strings"
	"time"
)

type Server struct {
	PublicKey   string
	Timeout     string
	TLSCertFile string
}
type Freshness struct {
	Threshold        string
	NumConfirmations int
}
type Config struct {
	Freshness Freshness
	Server    map[string]*Server
}

func NewClient(cfg *Config, dialer proxy.Dialer, tlsConfig *tls.Config) (c *Client, err error) {
	if cfg == nil {
		cfg = &DefaultConfig
	}
	c = new(Client)
	c.freshnessThreshold, err = time.ParseDuration(cfg.Freshness.Threshold)
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		tlsConfig = new(tls.Config)
	}
	if tlsConfig.Time == nil {
		tlsConfig.Time = time.Now
	}
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	c.freshnessNumConfirmations = cfg.Freshness.NumConfirmations
	c.servers = make(map[uint64]*serverInfo)
	for address, server := range cfg.Server {
		pkData, err := base64.StdEncoding.DecodeString(server.PublicKey)
		if err != nil {
			return nil, err
		}
		pk := new(Profile_PublicKey)
		if err = proto.Unmarshal(pkData, pk); err != nil {
			return nil, err
		}
		if server.Timeout == "" {
			server.Timeout = DefaultTimeout
		}
		timeout, err := time.ParseDuration(server.Timeout)
		if err != nil {
			return nil, err
		}
		serverTLSConfig := *tlsConfig
		serverTLSConfig.ServerName = strings.Split(address, ":")[0]
		if server.TLSCertFile != "" {
			certPEM, err := ioutil.ReadFile(server.TLSCertFile)
			if err != nil {
				return nil, err
			}
			serverTLSConfig.RootCAs = x509.NewCertPool()
			serverTLSConfig.RootCAs.AppendCertsFromPEM(certPEM)
		}
		c.servers[pk.ID()] = &serverInfo{pk: pk, address: address, timeout: timeout, tlsConfig: &serverTLSConfig}
	}
	c.consensusNumConfirmations = len(cfg.Server)
	if dialer == nil {
		dialer = DefaultDialer
	}
	c.dialer = dialer
	return c, nil
}
