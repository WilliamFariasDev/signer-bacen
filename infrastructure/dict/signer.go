package dict

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/lb-conn/test/signer/application/ports"
	"software.sslmate.com/src/go-pkcs12"
)

// Signer mantém a chave privada e certificado usados para assinar/verificar.
type Signer struct {
	privKey *rsa.PrivateKey
	cert    *x509.Certificate
}

var _ ports.Signer = (*Signer)(nil)

// NewSignerFromP12 carrega certificado e chave de um PKCS#12.
func NewSignerFromP12(p12byte []byte, password string) (*Signer, error) {
	priv, cert, err := pkcs12.Decode(p12byte, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS#12: %w", err)
	}
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("only RSA private keys are supported")
	}

	return &Signer{privKey: rsaKey, cert: cert}, nil
}
