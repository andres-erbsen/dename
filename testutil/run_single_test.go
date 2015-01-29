package testutil

import (
	"encoding/base64"
	"fmt"
	"github.com/andres-erbsen/dename/client"
	"os"
	"os/signal"
	"syscall"
	"testing"
)

func TestRunSingleServer(t *testing.T) {
	if os.Getenv("RUN_SINGLE_SERVER") == "" {
		t.Skip()
	}

	cfg, teardown := SingleServer(t)

	var addr string
	var server *client.Server
	for addr, server = range cfg.Server {
		break
	}
	fmt.Printf(`
[freshness]
Threshold = %s
NumConfirmations = %d

[server "%s"]
PublicKey = %s
TransportPublicKey = %s

`, cfg.Freshness.Threshold, cfg.Freshness.NumConfirmations, addr, server.PublicKey, server.TransportPublicKey)

	for i := 0; i < 10; i++ {
		fmt.Println(base64.StdEncoding.EncodeToString(MakeToken()))
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	<-sigc
	teardown()
}
