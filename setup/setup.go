package setup

import (
	"github.com/lb-conn/test/signer/application/usecases"
	"github.com/lb-conn/test/signer/infrastructure/dict"
)

// NewSetup cria a aplicação com o Signer carregado do PKCS#12.
func NewSetup(p12byte []byte, password string) (*usecases.Application, error) {
	signer, err := dict.NewSignerFromP12(p12byte, password)
	if err != nil {
		return nil, err
	}

	app := usecases.NewApplication(signer)
	return app, nil
}
