package dict

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Sign assina um documento XML e insere um <Signature> envelopado.
func (s *Signer) Sign(xmlData []byte) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	root := doc.Root()
	if root == nil {
		return nil, errors.New("empty XML document")
	}

	removeSignatureElements(root)
	canon := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	// 4.2) Digest do elemento raiz (aplicando enveloped: remove <Signature> antes da c14n)
	rootCopy := root.Copy()
	removeSignatureElements(rootCopy)
	rootCanon, err := canon.Canonicalize(rootCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize root: %w", err)
	}
	rootDigest := sha256.Sum256(rootCanon)
	rootDigestB64 := base64.StdEncoding.EncodeToString(rootDigest[:])

	// 5.2) Referência ao ROOT (URI="") com Enveloped + Exclusive C14N
	refRoot := etree.NewElement("ds:Reference")
	refRoot.CreateAttr("URI", "")
	refRootTransforms := etree.NewElement("ds:Transforms")
	envTransform := etree.NewElement("ds:Transform")
	envTransform.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
	refRootTransforms.AddChild(envTransform)
	canTransform := etree.NewElement("ds:Transform")
	canTransform.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	refRootTransforms.AddChild(canTransform)
	refRoot.AddChild(refRootTransforms)
	dmRoot := etree.NewElement("ds:DigestMethod")
	dmRoot.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	refRoot.AddChild(dmRoot)
	dvRoot := etree.NewElement("ds:DigestValue")
	dvRoot.SetText(rootDigestB64)
	refRoot.AddChild(dvRoot)

	// 2) Monta <ds:KeyInfo Id="..."><ds:X509Data><ds:X509IssuerSerial>…</ds:X509IssuerSerial></ds:X509Data></ds:KeyInfo> e adiciona DENTRO de <ds:Signature>
	keyID := randomID()
	keyInfo := etree.NewElement("ds:KeyInfo")
	keyInfo.CreateAttr("Id", keyID)
	keyInfo.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	x509Data := etree.NewElement("ds:X509Data")
	issuerSerial := etree.NewElement("ds:X509IssuerSerial")
	issuerName := etree.NewElement("ds:X509IssuerName")
	issuerName.SetText(s.cert.Issuer.String())
	serialNumber := etree.NewElement("ds:X509SerialNumber")
	serialNumber.SetText(s.cert.SerialNumber.String())
	issuerSerial.AddChild(issuerName)
	issuerSerial.AddChild(serialNumber)
	x509Data.AddChild(issuerSerial)
	keyInfo.AddChild(x509Data)

	// 4.1) Digest do KeyInfo no contexto do documento

	kiCopy := keyInfo.Copy()
	kiCanon, err := canon.Canonicalize(kiCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize KeyInfo: %w", err)
	}
	kiDigest := sha256.Sum256(kiCanon)
	kiDigestB64 := base64.StdEncoding.EncodeToString(kiDigest[:])

	// 5.1) Referência ao KeyInfo (URI="#<Id>") com Exclusive C14N
	refKI := etree.NewElement("ds:Reference")
	refKI.CreateAttr("URI", "#"+keyID)
	refKITransforms := etree.NewElement("ds:Transforms")
	refKITransform := etree.NewElement("ds:Transform")
	refKITransform.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	refKITransforms.AddChild(refKITransform)
	refKI.AddChild(refKITransforms)
	dmKI := etree.NewElement("ds:DigestMethod")
	dmKI.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	refKI.AddChild(dmKI)
	dvKI := etree.NewElement("ds:DigestValue")
	dvKI.SetText(kiDigestB64)
	refKI.AddChild(dvKI)

	// 3) Adiciona <ds:SignedInfo> (AINDA SEM referência) e anexa <Signature> ao root
	signedInfo := etree.NewElement("ds:SignedInfo")
	signedInfo.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	cm := etree.NewElement("ds:CanonicalizationMethod")
	cm.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	sm := etree.NewElement("ds:SignatureMethod")
	sm.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	signedInfo.AddChild(cm)
	signedInfo.AddChild(sm)
	// 5) Agora sim, crie as DUAS <Reference> dentro de <SignedInfo>
	signedInfo.AddChild(refKI)
	signedInfo.AddChild(refRoot)

	// 6) Canonicaliza o SignedInfo e assina (RSA-SHA256)
	siCopy := signedInfo.Copy()
	siCanon, err := canon.Canonicalize(siCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize SignedInfo: %w", err)
	}
	siHash := sha256.Sum256(siCanon)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, s.privKey, crypto.SHA256, siHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign SignedInfo: %w", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	// 1) Constrói <ds:Signature> com namespace
	signatureEl := etree.NewElement("ds:Signature")
	signatureEl.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	signatureEl.AddChild(signedInfo)

	sigVal := etree.NewElement("ds:SignatureValue")
	sigVal.SetText(sigB64)
	signatureEl.AddChild(sigVal)
	signatureEl.AddChild(keyInfo)

	// Anexa <Signature> ao root AGORA, para que KeyInfo esteja no contexto final
	root.AddChild(signatureEl)

	// 4) Calcula digests

	// pronto: root já contém <Signature> completo
	out := etree.NewDocument()
	out.SetRoot(root)

	return out.WriteToBytes()
}
