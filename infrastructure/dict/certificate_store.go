package dict

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/beevik/etree"
)

// CertificateStore representa um repositório de certificados confiáveis
type CertificateStore struct {
	certificates map[string]*x509.Certificate // chave: "issuer:serialNumber"
}

// NewCertificateStore cria um novo repositório de certificados
func NewCertificateStore() *CertificateStore {
	return &CertificateStore{
		certificates: make(map[string]*x509.Certificate),
	}
}

// AddCertificate adiciona um certificado ao repositório
func (cs *CertificateStore) AddCertificate(cert *x509.Certificate) {
	key := cs.makeCertificateKey(cert.Issuer.String(), cert.SerialNumber.String())
	cs.certificates[key] = cert
}

// GetCertificateFromKeyInfo obtém o certificado baseado nas informações do KeyInfo
func (cs *CertificateStore) GetCertificateFromKeyInfo(keyInfo *etree.Element) (*x509.Certificate, error) {
	// Extrai X509IssuerSerial do KeyInfo
	x509Data := keyInfo.FindElement(".//ds:X509Data")
	if x509Data == nil {
		x509Data = keyInfo.FindElement(".//X509Data")
	}
	if x509Data == nil {
		return nil, errors.New("X509Data not found in KeyInfo")
	}

	issuerSerial := x509Data.FindElement(".//ds:X509IssuerSerial")
	if issuerSerial == nil {
		issuerSerial = x509Data.FindElement(".//X509IssuerSerial")
	}
	if issuerSerial == nil {
		return nil, errors.New("X509IssuerSerial not found in KeyInfo")
	}

	issuerName := issuerSerial.FindElement(".//ds:X509IssuerName")
	if issuerName == nil {
		issuerName = issuerSerial.FindElement(".//X509IssuerName")
	}
	serialNumber := issuerSerial.FindElement(".//ds:X509SerialNumber")
	if serialNumber == nil {
		serialNumber = issuerSerial.FindElement(".//X509SerialNumber")
	}

	if issuerName == nil || serialNumber == nil {
		return nil, errors.New("incomplete X509IssuerSerial information")
	}

	issuerStr := strings.TrimSpace(issuerName.Text())
	serialStr := strings.TrimSpace(serialNumber.Text())

	// Busca o certificado no repositório
	key := cs.makeCertificateKey(issuerStr, serialStr)
	cert, exists := cs.certificates[key]
	if !exists {
		return nil, fmt.Errorf("certificate not found for issuer: %s, serial: %s", issuerStr, serialStr)
	}

	return cert, nil
}

// makeCertificateKey cria uma chave única para o certificado
func (cs *CertificateStore) makeCertificateKey(issuer, serial string) string {
	return fmt.Sprintf("%s:%s", issuer, serial)
}

// LoadBacenCertificates carrega os certificados do BACEN
// Esta função deve ser implementada para carregar os certificados do BACEN
// de um local seguro (arquivo, base de dados, etc.)
func (cs *CertificateStore) LoadBacenCertificates() error {
	files := []string{
		"../certs/bacen/example.pem",
	}

	for _, file := range files {
		certPEM, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read certificate file %s: %w", file, err)
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			return fmt.Errorf("failed to parse certificate PEM in file %s", file)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate in file %s: %w", file, err)
		}

		cs.AddCertificate(cert)
	}
	return nil
}

// ValidateCertificate verifica se o certificado é válido e confiável
func (cs *CertificateStore) ValidateCertificate(cert *x509.Certificate) error {
	// TODO: Implementar validação do certificado
	// - Verificar se não está expirado
	// - Verificar cadeia de certificação
	// - Verificar se está na lista de certificados confiáveis do BACEN

	return nil
}
