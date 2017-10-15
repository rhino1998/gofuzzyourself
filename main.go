package main

import (
	"flag"
	"log"
	"os"

	"github.com/rhino1998/gofuzzyourself/fuzzer"
)

func main() {
	flag.Parse()

	fileName := flag.Arg(0)
	if fileName == "" {
		log.Fatalf("Invalid fuzzer definition: %s", fileName)
	}

	file, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("Error opening config file: %v", err)
	}
	_, err = fuzzer.ParseConfig(fileName, file)
	if err != nil {
		log.Fatalf("Error parsing config file: %v", err)
	}
}
