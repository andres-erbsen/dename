package testutil

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/agl/ed25519"
	. "github.com/andres-erbsen/dename/client"
	. "github.com/andres-erbsen/dename/protocol"
	"golang.org/x/crypto/nacl/box"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

var INVITE_KEY = []byte("very secret text in the source")

func MakeToken() []byte {
	var r [8]byte
	rand.Read(r[:])
	mac := hmac.New(sha256.New, INVITE_KEY)
	mac.Write(r[:])
	return append(r[:], mac.Sum(nil)[:8]...)
}

func CreateConfigs(t *testing.T, numCoreServers, numVerifiers, numSubscribers uint) (dirs []string, clientConfig *Config, teardown func()) {
	n := numCoreServers + numVerifiers + numSubscribers
	dir, err := ioutil.TempDir("", "servertest")
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]uint64, n)
	pks := make(map[uint64]*Profile_PublicKey, n)
	transportPKs := make(map[uint64]*[32]byte, n)
	dirMap := make(map[uint64]string, n)
	dirs = make([]string, 0, n)
	configs := make(map[uint64]string, n)
	for i := uint(0); i < n; i++ {
		pkEd, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		transportPK, transportSK, err := box.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		pk := &Profile_PublicKey{Ed25519: pkEd[:]}
		id := pk.ID()
		ids[i] = id
		pks[id] = pk
		transportPKs[id] = transportPK
		dir := filepath.Join(dir, fmt.Sprintf("%x", id))
		dirs = append(dirs, dir)
		dirMap[id] = dir
		err = os.Mkdir(dir, os.FileMode(0700))
		if err != nil {
			t.Fatal(err)
		}
		ioutil.WriteFile(filepath.Join(dir, "sk"), sk[:], os.FileMode(0600))
		ioutil.WriteFile(filepath.Join(dir, "invitekey"), INVITE_KEY, os.FileMode(0600))
		ioutil.WriteFile(filepath.Join(dir, "transport.sk"), transportSK[:], os.FileMode(0600))
		configs[id] = fmt.Sprintf(`[backend]
DataDirectory = %s
SigningKeyPath = %s
Listen = 127.0.0.1:198%d

[frontend]
InviteKeyPath = %s
TransportKeyPath = %s
Listen = 127.0.0.1:144%d
`, dir, filepath.Join(dir, "sk"), i, filepath.Join(dir, "invitekey"), filepath.Join(dir, "transport.sk"), i)
	}
	for left_i, left_id := range ids {
		putConf := func(i uint) {
			configs[left_id] += fmt.Sprintf(`
[server "127.0.0.1:198%d"]
PublicKey = %s
IsCore = %t
`, i, base64.StdEncoding.EncodeToString(PBEncode(pks[ids[i]])), i < numCoreServers)
		}
		for i := uint(0); i < numCoreServers+numVerifiers; i++ {
			putConf(i)
		}
		if uint(left_i) >= numCoreServers+numVerifiers { // put the server itself in its peers irrespectively of stuff
			putConf(uint(left_i))
		}
		ioutil.WriteFile(filepath.Join(dirMap[left_id], "denameserver.cfg"), []byte(configs[left_id]), os.FileMode(0600))
	}
	cfg := new(Config)
	cfg.Freshness = DefaultFreshness
	cfg.Update = make(map[string]*Server)
	cfg.Lookup = make(map[string]*Server)
	cfg.Verifier = make([]string, 0, len(ids))
	for i, id := range ids {
		cfg.Verifier = append(cfg.Verifier, base64.StdEncoding.EncodeToString(PBEncode(pks[id])))
		addr := fmt.Sprintf("127.0.0.1:144%d", i)
		details := &Server{TransportPublicKey: base64.StdEncoding.EncodeToString(transportPKs[id][:])}
		cfg.Lookup[addr] = details
		if i < int(numCoreServers) {
			cfg.Update[addr] = details
		}
	}
	return dirs, cfg, func() {
		os.RemoveAll(dir)
	}
}
