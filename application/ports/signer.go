package ports

type Signer interface {
	Sign(xmlData []byte) ([]byte, error)
	Verify(xmlData []byte) error
}
