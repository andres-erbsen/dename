package main

import (
	"github.com/andres-erbsen/dename/denameserver"
	"os"
)

func main() {
	denameserver.StartFromConfigFile(os.Args[1])
	select {}
}
