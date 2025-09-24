package test

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	_uuid "github.com/google/uuid"
	"github.com/lb-conn/sdk-rsfn-validator/libs/dict/pkg/bacen"
	"github.com/lb-conn/sdk-rsfn-validator/libs/dict/pkg/bacen/directory"
	"github.com/lb-conn/test/signer/setup"
)

func TestMain_Sign(t *testing.T) {
	embeddedP12, err := os.ReadFile("../certs/lb_client.p12")
	if err != nil {
		t.Fatalf("failed to read PKCS#12 file: %v", err)
	}

	signer, err := setup.NewSetup(embeddedP12, "example")
	if err != nil {
		t.Fatalf("failed to load PKCS#12: %v", err)
	}

	// Prepare the test data - converting the provided JSON example to proper Go structs
	openingDate, err := time.Parse(time.RFC3339, "2023-08-24T14:15:22Z")
	if err != nil {
		t.Fatalf("failed to parse opening date: %v", err)
	}

	branch := "0001"
	key := _uuid.NewString()

	// Create Entry with proper types
	entry := bacen.Entry{
		Key:     key,
		KeyType: bacen.EVP,
		Account: bacen.BrazilianAccount{
			Participant:   "12345678", // 8 digits as required by validation
			Branch:        &branch,
			AccountNumber: "1234567890",
			AccountType:   bacen.CACC,
			OpeningDate:   openingDate,
		},
		Owner: bacen.NaturalPersonAsPerson(&bacen.NaturalPerson{
			Type:        "NATURAL_PERSON",
			TaxIDNumber: "12345678901", // 11 digits CPF
			Name:        "João da Silva",
		}),
	}

	// Create the request
	request := directory.CreateEntryRequest{
		Entry:     entry,
		Reason:    bacen.UserRequested,
		RequestID: "b1d2c3e3-f5a6-0718-293a-4b5c6d7e8fdd",
	}

	data, err := xml.Marshal(request)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	resp, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("error signing XML: %v", err)
	}

	println("-----------------------------------")
	fmt.Printf("Bytes after sign: %s\n", string(resp))
	println("-----------------------------------")

	// Verifica se o XML está bem formado
	err = IsXMLWellFormed(resp)
	if err != nil {
		t.Fatalf("signed XML is not well-formed: %v", err)
	}

	err = signer.Verify(resp) // Verifica a assinatura do XML assinado
	if err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	t.Logf("Signed XML:\n%s", resp)
}

func IsXMLWellFormed(b []byte) error {
	// trate vazio como inválido, se quiser
	if len(bytes.TrimSpace(b)) == 0 {
		return fmt.Errorf("documento vazio")
	}

	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = true // padrão já é true; garante bem-formação estrita

	// Varra todos os tokens até EOF.
	for {
		_, err := dec.Token()
		if err == io.EOF {
			return nil // OK: bem-formado
		}
		if err != nil {
			return err // Não é bem-formado (posição e motivo no erro)
		}
	}
}
