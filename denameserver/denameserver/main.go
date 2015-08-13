package main

import (
	"github.com/andres-erbsen/dename/server"
	"os"
)

func main() {
	server.StartFromConfigFile(os.Args[1])
	select {}
}
