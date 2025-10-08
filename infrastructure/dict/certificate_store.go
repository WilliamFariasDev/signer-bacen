package dict

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
// Lista automaticamente todos os arquivos .pem na pasta certs/bacen
func (cs *CertificateStore) LoadBacenCertificates() error {
	certsDir := "certs/bacen"

	// Verifica se o diretório existe
	if _, err := os.Stat(certsDir); os.IsNotExist(err) {
		return fmt.Errorf("certificates directory not found: %s", certsDir)
	}

	// Lista todos os arquivos .pem no diretório
	pemFiles, err := filepath.Glob(filepath.Join(certsDir, "*.pem"))
	if err != nil {
		return fmt.Errorf("failed to list certificate files in %s: %w", certsDir, err)
	}

	if len(pemFiles) == 0 {
		return fmt.Errorf("no .pem certificate files found in %s", certsDir)
	}

	fmt.Printf("Loading BACEN certificates from %s...\n", certsDir)

	for _, file := range pemFiles {
		if err := cs.loadCertificateFile(file); err != nil {
			return fmt.Errorf("failed to load certificate %s: %w", file, err)
		}
		fmt.Printf("✓ Loaded certificate: %s\n", filepath.Base(file))
	}

	fmt.Printf("Successfully loaded %d BACEN certificate(s)\n", len(pemFiles))
	return nil
}

// loadCertificateFile carrega um arquivo de certificado individual
func (cs *CertificateStore) loadCertificateFile(filePath string) error {
	certPEM, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Suporta múltiplos certificados em um arquivo
	for len(certPEM) > 0 {
		var block *pem.Block
		block, certPEM = pem.Decode(certPEM)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue // Pula blocos que não são certificados
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}

		cs.AddCertificate(cert)
		fmt.Printf("  - Added: %s (Serial: %s)\n",
			cert.Subject.CommonName, cert.SerialNumber.String())
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
