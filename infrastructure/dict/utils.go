package dict

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

// generate a pseudo‑random Id for KeyInfo.
func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("KI%x", b)
	}
	return fmt.Sprintf("KI%x", b)
}

// removeSignatureElements elimina quaisquer elementos <Signature> existentes (transform enveloped).
func removeSignatureElements(el *etree.Element) {
	var newChildren []etree.Token
	for _, child := range el.Child {
		switch c := child.(type) {
		case *etree.Element:
			if strings.EqualFold(c.Tag, "Signature") || strings.HasSuffix(c.Tag, ":Signature") {
				continue
			}
			removeSignatureElements(c)
			newChildren = append(newChildren, c)
		default:
			newChildren = append(newChildren, c)
		}
	}
	el.Child = newChildren
}

// removeWhitespaceNodes remove nós de texto que contêm apenas espaços em branco
func removeWhitespaceNodes(el *etree.Element) {
	var newChildren []etree.Token
	for _, child := range el.Child {
		switch c := child.(type) {
		case *etree.Element:
			removeWhitespaceNodes(c)
			newChildren = append(newChildren, c)
		case *etree.CharData:
			// Remove apenas se for apenas espaços em branco
			text := strings.TrimSpace(c.Data)
			if text != "" {
				newChildren = append(newChildren, c)
			}
		default:
			newChildren = append(newChildren, c)
		}
	}
	el.Child = newChildren
}

// PrintElement prints an XML element for debugging purposes.
func PrintElement(element *etree.Element) {
	// print element for debug
	var buf bytes.Buffer
	settings := &etree.WriteSettings{
		CanonicalEndTags: true,
		CanonicalText:    true,
		CanonicalAttrVal: true,
	}
	element.WriteTo(&buf, settings)
	str := buf.String()
	fmt.Println("element:", str)
}
