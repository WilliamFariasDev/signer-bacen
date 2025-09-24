package main

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/lb-conn/test/signer/setup"
)

//go:embed lb_client.p12
var embeddedP12 []byte

// O CLI lê um XML da entrada padrão, assina ou valida de acordo com as flags e escreve na saída padrão.
func main() {
	mode := flag.String("mode", "", "operation to perform: sign or verify")
	p12Path := flag.String("p12", "", "path to PKCS#12 file containing certificate and private key")
	pass := flag.String("pass", "", "password for PKCS#12 or encrypted private key (if needed)")
	filePath := flag.String("file", "", "path to XML file to sign or verify")
	data := flag.String("data", "", "XML content as a string (optional; takes precedence over --file)")
	flag.Parse()

	if *mode != "sign" && *mode != "verify" && *mode != "test" {
		log.Fatalf("invalid or missing mode: must be 'sign' or 'verify' or 'test'")
	}

	if *mode == "test" {
		fmt.Println("test mode: OK")
		return
	}

	if strings.TrimSpace(*pass) == "" {
		log.Fatalf("missing password for PKCS#12")
	}

	// Determine XML input: --data > --file > stdin
	var xmlData []byte
	var err error

	switch {
	case strings.TrimSpace(*data) != "":
		xmlData = []byte(*data)
	case strings.TrimSpace(*filePath) != "":
		xmlData, err = os.ReadFile(*filePath)
		if err != nil {
			log.Fatalf("failed to read input file: %v", err)
		}
	default:
		xmlData, err = os.ReadFile("/dev/stdin")
		if err != nil {
			log.Fatalf("failed to read from stdin: %v", err)
		}
	}

	// If no --p12 provided
	if strings.TrimSpace(*p12Path) != "" {
		if _, err := os.Stat(*p12Path); os.IsNotExist(err) {
			log.Fatalf("PKCS#12 file does not exist: %s", *p12Path)
		}

		embeddedP12, err = os.ReadFile(*p12Path)
		if err != nil {
			log.Fatalf("failed to read PKCS#12 file: %v", err)
		}
	}

	signer, err := setup.NewSetup(embeddedP12, *pass)
	if err != nil {
		log.Fatalf("failed to load PKCS#12: %v", err)
	}

	switch *mode {
	case "sign":
		signed, err := signer.Sign(xmlData)
		if err != nil {
			log.Fatalf("error signing XML: %v", err)
		}
		if _, err := os.Stdout.Write(signed); err != nil {
			log.Fatalf("failed to write output: %v", err)
		}
	case "verify":
		if err := signer.Verify(xmlData); err != nil {
			log.Fatalf("signature verification failed: %v", err)
		}
		fmt.Fprintln(os.Stdout, "signature valid")
	default:
		log.Fatal(errors.New("unsupported mode"))
	}
}
