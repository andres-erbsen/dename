package testutil

import (
	"github.com/andres-erbsen/dename/client"
	"github.com/andres-erbsen/dename/server"
	"github.com/andres-erbsen/dename/server/testutil"
	"path/filepath"
	"testing"
)

func MakeToken() []byte {
	return testutil.MakeToken()
}

// SingleServer starts a dename server and returns the corresponding client
// configuration and a function that will stop the server when called.
func SingleServer(t testing.TB) (*client.Config, func()) {
	dirs, cfg, teardown := testutil.CreateConfigs(t, 1, 0, 0)
	s := server.StartFromConfigFile(filepath.Join(dirs[0], "denameserver.cfg"))
	return cfg, func() {
		s.Shutdown()
		teardown()
	}
}
