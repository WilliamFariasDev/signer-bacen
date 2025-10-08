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

// Sign assina um documento XML e insere um elemento <ds:Signature> enveloped
// (assinatura envelopada: a própria assinatura é inserida dentro do documento
// assinado). A função implementa os passos necessários para construir um
// SignedInfo com duas referências (KeyInfo e Root), calcular digests, assinar
// com RSA-SHA256 e anexar <ds:Signature> ao elemento raiz.
func (s *Signer) Sign(xmlData []byte) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	// Obtém o conteúdo do elemento raiz do XML
	root := doc.Root()
	if root == nil {
		return nil, errors.New("empty XML document")
	}

	// Preparar o documento: remover quaisquer elementos <Signature> (transform enveloped)
	removeSignatureElements(root)

	// Preparar o canonicalizador Exclusive C14N (sem prefixos adicionais)
	canon := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	// Realiza transform de enveloped signature
	rootCopy := root.Copy()
	removeSignatureElements(rootCopy)
	// Remove espaços em branco desnecessários para consistência
	removeWhitespaceNodes(rootCopy)

	// Realiza transform de canonicalização
	rootCanon, err := canon.Canonicalize(rootCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize root: %w", err)
	}
	// Calcula o digest SHA256 do root canonicizado
	rootDigest := sha256.Sum256(rootCanon)
	rootDigestB64 := base64.StdEncoding.EncodeToString(rootDigest[:])

	// Construir a <ds:Reference> ao ROOT (URI="") com os transforms:
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

	// Constói o elemento <ds:KeyInfo Id="..."> contendo <ds:X509Data> e <ds:X509IssuerSerial>
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

	// Realiza o transform de canonicalização
	kiCopy := keyInfo.Copy()
	// Remove espaços em branco desnecessários do KeyInfo
	removeWhitespaceNodes(kiCopy)
	kiCanon, err := canon.Canonicalize(kiCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize KeyInfo: %w", err)
	}
	// Calcula o digest SHA256 do KeyInfo canonicizado
	kiDigest := sha256.Sum256(kiCanon)
	kiDigestB64 := base64.StdEncoding.EncodeToString(kiDigest[:])

	// Constói o elemento <ds:Reference> para o KeyInfo (URI="#<Id>") com o
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

	// Constói o elemento <ds:SignedInfo> com CanonicalizationMethod e SignatureMethod
	signedInfo := etree.NewElement("ds:SignedInfo")
	signedInfo.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	cm := etree.NewElement("ds:CanonicalizationMethod")
	cm.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	sm := etree.NewElement("ds:SignatureMethod")
	sm.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	signedInfo.AddChild(cm)
	signedInfo.AddChild(sm)
	// Anexa as duas <Reference> (KeyInfo e Root) dentro de <SignedInfo>.
	signedInfo.AddChild(refKI)
	signedInfo.AddChild(refRoot)

	// Canonicaliza o SignedInfo
	siCopy := signedInfo.Copy()
	// Remove espaços em branco desnecessários do SignedInfo
	removeWhitespaceNodes(siCopy)
	siCanon, err := canon.Canonicalize(siCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize SignedInfo: %w", err)
	}
	// Efetua a assinatura RSA-SHA256 do hash do SignedInfo canonicizado
	siHash := sha256.Sum256(siCanon)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, s.privKey, crypto.SHA256, siHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign SignedInfo: %w", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	// Constói o elemento <ds:Signature> com SignedInfo, SignatureValue e KeyInfo
	signatureEl := etree.NewElement("ds:Signature")
	signatureEl.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	signatureEl.AddChild(signedInfo)

	// Adiciona <SignatureValue>
	sigVal := etree.NewElement("ds:SignatureValue")
	sigVal.SetText(sigB64)
	signatureEl.AddChild(sigVal)
	signatureEl.AddChild(keyInfo)

	// Anexa <Signature> ao root. Neste momento o documento contém o
	// elemento <ds:Signature> completo e pode ser serializado.
	root.AddChild(signatureEl)
	out := etree.NewDocument()
	out.SetRoot(root)

	return out.WriteToBytes()
}
