package main

import (
	"github.com/andres-erbsen/dename/tlsproxy"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 6 {
		log.Printf("USAGE: %s <tlsCertPath> <tlsKeyPath> <listenAddr> <connectAddr> <connectPKPath>", os.Args[0])
		os.Exit(2)
	}
	_, err := tlsproxy.RunTLSProxy(os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5], 1<<12)
	if err != nil {
		log.Printf("tlsproxy startup failed: %s", err)
		os.Exit(1)
	}
	select {}
}
