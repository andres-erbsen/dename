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

	var name, addr string
	var server *client.Server
	var verifier *client.Verifier
	for name, verifier = range cfg.Verifier {
		break
	}
	for addr, server = range cfg.Update {
		break
	}
	fmt.Printf(`
[consensus]
SignaturesRequired = %d

[freshness]
SignaturesRequired = %d
Threshold = %s

[verifier "%s"]
PublicKey = %s

[update "%s"]
TransportPublicKey = %s

[lookup "%s"]
TransportPublicKey = %s

`, cfg.Consensus.SignaturesRequired, cfg.Freshness.SignaturesRequired, cfg.Freshness.Threshold, name, verifier.PublicKey, addr, server.TransportPublicKey, addr, server.TransportPublicKey)

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
