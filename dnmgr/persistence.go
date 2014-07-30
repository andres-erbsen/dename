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
package dnmgr

import (
	"code.google.com/p/gcfg"
	"code.google.com/p/goprotobuf/proto"
	dnmc "github.com/andres-erbsen/dename/client"
	. "github.com/andres-erbsen/dename/protocol"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// ErrExists that the file/profile being created already exists
var ErrExist = os.ErrExist
var defaultConfigDir = filepath.Join(os.Getenv("HOME"), ".config", "dename")

func dirAndClient(configDir string, client *dnmc.Client) (string, *dnmc.Client, error) {
	if configDir == "" {
		configDir = defaultConfigDir
	}
	if client == nil {
		clientCfg := new(dnmc.Config)
		err := gcfg.ReadFileInto(clientCfg, filepath.Join(configDir, "authorities.cfg"))
		if os.IsNotExist(err) {
			clientCfg = nil
		} else if err != nil {
			return "", nil, err
		}
		client, err = dnmc.NewClient(clientCfg, nil, nil)
		if err != nil {
			return "", nil, err
		}
	}
	return configDir, client, nil
}

func filename(s []byte) string {
	return string(s) // TODO: sanitize
}

// Register registers associates name with profile and persists the secret key
// and the profile on disk.
func Register(sk *[64]byte, profile *Profile, name []byte, invite []byte, configDir string, client *dnmc.Client) error {
	configDir, client, err := dirAndClient(configDir, client)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}
	path := filepath.Join(configDir, filename(name))
	if _, err := os.Stat(path); err == nil {
		return ErrExist
	}
	if err = os.MkdirAll(path, 0700); err != nil {
		return err
	}
	if err = ioutil.WriteFile(filepath.Join(path, "sk"), sk[:], 0600); err != nil {
		return err
	}
	// TODO: provide an API for setting fields
	err = client.Register(sk, name, profile, invite)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(path, "profile"), PBEncode(profile), 0600)
}

// LoadLocalProfile returns the secret key and the profile that are locally
// known to be correspond to name. This information is not guaranteed to be
// current -- if a fresh profile is needed, use client.Lookup instead.
func LoadLocalProfile(name []byte, configDir string) (sk *[64]byte, profile *Profile, err error) {
	if configDir == "" {
		configDir = defaultConfigDir
	}
	path := filepath.Join(configDir, filename(name))
	if _, err = os.Stat(path); err != nil {
		return
	}
	sk = new([64]byte)
	if skData, err := ioutil.ReadFile(filepath.Join(path, "sk")); err != nil {
		return nil, nil, err
	} else if len(skData) != 64 {
		return nil, nil, fmt.Errorf("malformed secret key (expected %d bytes, got %d)", 64, len(skData))
	} else {
		copy(sk[:], skData)
	}
	profileData, err := ioutil.ReadFile(filepath.Join(path, "profile"))
	if err != nil {
		return
	}
	profile = new(Profile)
	err = proto.Unmarshal(profileData, profile)
	return
}

// SetProfileField downloads the profile for name, sets the value of a field
// and uses sk to remap the name to the old profile. The local copy of the
// profile is ignored and overwritten.
func SetProfileField(name []byte, field int32, value []byte, configDir string, client *dnmc.Client) error {
	configDir, client, err := dirAndClient(configDir, client)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}
	sk, _, err := LoadLocalProfile(name, configDir)
	if err != nil {
		return err
	}
	profile, err := client.Lookup(name)
	if err != nil {
		return err
	}
	version := profile.GetVersion()
	profile.Version = new(uint64)
	*profile.Version = version + 1
	if err := dnmc.SetProfileField(profile, field, value); err != nil {
		return err
	}
	if err := client.Modify(sk, name, profile); err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(configDir, filename(name), "profile"), PBEncode(profile), 0600)
}
