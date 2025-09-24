package usecases

import "github.com/lb-conn/test/signer/application/ports"

// Application holds the dependencies for antifraud operations.
type Application struct {
	signer ports.Signer
}

// NewApplication creates a new instance of the Application with the provided dependencies.
func NewApplication(signer ports.Signer) *Application {
	return &Application{
		signer: signer,
	}
}

// Sign signs the provided data using the Signer service.
func (app *Application) Sign(data []byte) ([]byte, error) {
	return app.signer.Sign(data)
}

// Verify verifies the provided signature against the data using the Signer service.
func (app *Application) Verify(data []byte) error {
	return app.signer.Verify(data)
}
