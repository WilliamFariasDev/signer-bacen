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
	store   *CertificateStore
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

	store, err := LoadBacenCertificates(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to load BACEN certificates: %w", err)
	}

	return &Signer{privKey: rsaKey, cert: cert, store: store}, nil
}

// LoadBacenCertificates carrega os certificados raiz do BACEN.
func LoadBacenCertificates(cert *x509.Certificate) (*CertificateStore, error) {
	certStore := NewCertificateStore()

	// Adiciona o certificado do signer (nosso) ao repositório de certificados confiáveis
	certStore.AddCertificate(cert)

	if err := certStore.LoadBacenCertificates(); err != nil {
		return nil, err
	}

	return certStore, nil
}
