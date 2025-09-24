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
	root := doc.Root()
	if root == nil {
		return errors.New("empty XML document")
	}

	canon := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	// Aplicar o transform “Enveloped Signature” no conteúdo;
	rootCopy := root.Copy()
	removeSignatureElements(rootCopy)

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

	// canonizar o root
	rootCanon, err := canon.Canonicalize(rootCopy)
	if err != nil {
		return fmt.Errorf("failed to canonicalize root: %w", err)
	}
	rootDigest := sha256.Sum256(rootCanon)
	rootDigestB64 := base64.StdEncoding.EncodeToString(rootDigest[:])

	// canonizar o KeyInfo
	kiCopy := keyInfo.Copy()
	kiCanon, err := canon.Canonicalize(kiCopy)
	if err != nil {
		return fmt.Errorf("failed to canonicalize KeyInfo: %w", err)
	}
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

	// compara digest

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

	if kiDigestB64 != kiDigestFromSig {
		return errors.New("KeyInfo digest mismatch")
	}

	// Verifica assinatura sobre SignedInfo

	siCopy := signedInfo.Copy()
	siCanon, err := canon.Canonicalize(siCopy)
	if err != nil {
		return fmt.Errorf("failed to canonicalize SignedInfo: %w", err)
	}
	siHash := sha256.Sum256(siCanon)
	sigBytes, err := base64.StdEncoding.DecodeString(signatureValue)
	if err != nil {
		return fmt.Errorf("signature value is not valid base64: %w", err)
	}
	pub, ok := s.cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("certificate does not contain an RSA public key")
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, siHash[:], sigBytes); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}
