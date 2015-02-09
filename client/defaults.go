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
)

var (
	DefaultVerifiers          = map[string]*Verifier{"mit-pilot": &Verifier{"CiCheFqDmJ0Pg+j+lypkmmiHrFmRn50rlDi5X0l4+lJRFA=="}}
	DefaultServers            = map[string]*Server{"dename.mit.edu:6263": &Server{TransportPublicKey: "4f2i+j65JCE2xNKhxE3RPurAYALx9GRy0Pm9c6J7eDY="}}
	DefaultTimeout            = "10s"
	DefaultFreshnessThreshold = "60s"
	DefaultFreshness          = Freshness{SignaturesRequired: len(DefaultVerifiers), Threshold: DefaultFreshnessThreshold}
	DefaultConfig             = Config{Verifier: DefaultVerifiers, Lookup: DefaultServers, Update: DefaultServers}
	DefaultDialer             = proxy.FromEnvironment()
)
