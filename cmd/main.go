package main

import (
	"log"

	"github.com/yhbsh/smp"
)

func main() {
	s := smp.New(smp.Config{
		Addr:     ":7777",
		LogLevel: smp.InfoLevel,
	})
	log.Fatal(s.Run())
}
