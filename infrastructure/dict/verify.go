package dict

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Verify valida a assinatura de um documento DICT XML usando o certificado do signer.
func (s *Signer) Verify(xmlData []byte) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return fmt.Errorf("failed to parse XML: %w", err)
	}

	// Obtém o conteúdo do elemento raiz do XML
	root := doc.Root()
	if root == nil {
		return errors.New("empty XML document")
	}

	// Preparar o canonicalizador Exclusive C14N (sem prefixos adicionais)
	canon := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	// Realiza transform de enveloped signature
	rootCopy := root.Copy()
	removeSignatureElements(rootCopy)
	// Remove espaços em branco desnecessários para compatibilidade com assinatura do BACEN
	removeWhitespaceNodes(rootCopy)

	// Realiza transform de canonicalização
	rootCanon, err := canon.Canonicalize(rootCopy)
	if err != nil {
		return fmt.Errorf("failed to canonicalize root: %w", err)
	}

	// Calcula o digest SHA256 do root canonicizado
	rootDigest := sha256.Sum256(rootCanon)
	rootDigestB64 := base64.StdEncoding.EncodeToString(rootDigest[:])

	// Encontra elemento Signature
	var sigEl *etree.Element
	for _, child := range root.Child {
		if el, ok := child.(*etree.Element); ok {
			if strings.EqualFold(el.Tag, "Signature") || strings.HasSuffix(el.Tag, ":Signature") {
				sigEl = el
				break
			}
		}
	}
	if sigEl == nil {
		return errors.New("signature element not found")
	}

	// Extrai SignedInfo, SignatureValue e KeyInfo
	var signedInfo *etree.Element
	var signatureValue string
	var keyInfo *etree.Element
	for _, child := range sigEl.Child {
		if el, ok := child.(*etree.Element); ok {
			switch strings.TrimPrefix(el.Tag, "ds:") {
			case "SignedInfo":
				signedInfo = el
			case "SignatureValue":
				signatureValue = strings.TrimSpace(el.Text())
			case "KeyInfo":
				keyInfo = el
			}
		}
	}

	if signedInfo == nil || keyInfo == nil || signatureValue == "" {
		return errors.New("incomplete signature structure")
	}

	// Realiza o transform de canonicalização
	kiCopy := keyInfo.Copy()
	// Garante que o namespace ds esteja declarado no KeyInfo para canonicalização
	if kiCopy.SelectAttr("xmlns:ds") == nil {
		kiCopy.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	}
	// Remove espaços em branco desnecessários do KeyInfo
	removeWhitespaceNodes(kiCopy)
	kiCanon, err := canon.Canonicalize(kiCopy)
	if err != nil {
		return fmt.Errorf("failed to canonicalize KeyInfo: %w", err)
	}

	// Calcula o digest SHA256 do KeyInfo canonicizado
	kiDigest := sha256.Sum256(kiCanon)
	kiDigestB64 := base64.StdEncoding.EncodeToString(kiDigest[:])

	// Recupera digests das referências em SignedInfo
	refs := signedInfo.FindElements(".//ds:Reference")
	if len(refs) == 0 {
		refs = signedInfo.FindElements(".//Reference")
	}
	var kiDigestFromSig, rootDigestFromSig string
	var kiURI string
	for _, ref := range refs {
		uri := ""
		if attr := ref.SelectAttr("URI"); attr != nil {
			uri = attr.Value
		}
		dv := ref.FindElement(".//ds:DigestValue")
		if dv == nil {
			dv = ref.FindElement(".//DigestValue")
		}
		if dv == nil {
			continue
		}
		digestVal := strings.TrimSpace(dv.Text())
		if uri == "" {
			rootDigestFromSig = digestVal
		} else if strings.HasPrefix(uri, "#") {
			kiDigestFromSig = digestVal
			kiURI = uri[1:]
		}
	}
	if kiDigestFromSig == "" || rootDigestFromSig == "" {
		return errors.New("missing digest values in SignedInfo")
	}

	// compara digest gerado com o do elemento Reference
	if rootDigestB64 != rootDigestFromSig {
		return errors.New("root digest mismatch")
	}

	idAttr := keyInfo.SelectAttr("Id")
	if idAttr == nil || idAttr.Value == "" {
		return errors.New("KeyInfo missing Id attribute")
	}

	if idAttr.Value != kiURI {
		return fmt.Errorf("KeyInfo Id (%s) does not match reference URI (#%s)", idAttr.Value, kiURI)
	}

	// compara digest gerado com o do elemento Reference
	if kiDigestB64 != kiDigestFromSig {
		return errors.New("KeyInfo digest mismatch")
	}

	// Realiza o transform de canonicalização de SignedInfo
	siCopy := signedInfo.Copy()
	// Garante que o namespace ds esteja declarado no SignedInfo para canonicalização
	if siCopy.SelectAttr("xmlns:ds") == nil {
		siCopy.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	}
	siCanon, err := canon.Canonicalize(siCopy)
	if err != nil {
		return fmt.Errorf("failed to canonicalize SignedInfo: %w", err)
	}

	// Verifica a assinatura usando a chave pública do certificado
	siHash := sha256.Sum256(siCanon)
	sigBytes, err := base64.StdEncoding.DecodeString(signatureValue)
	if err != nil {
		return fmt.Errorf("signature value is not valid base64: %w", err)
	}

	// TODO buscar em um repositório local de certificados confiáveis, recuperar o certificado X.509 completo do emissor e então verificar a assinatura com a chave pública desse certificado
	pub, ok := s.cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("certificate does not contain an RSA public key")
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, siHash[:], sigBytes); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}
