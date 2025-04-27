package main

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

// InitWebAuthn initializes the WebAuthn configuration
func InitWebAuthn() (*webauthn.WebAuthn, error) {
    // Configuration for WebAuthn
    config := &webauthn.Config{
        RPDisplayName: "Go Passkey Auth Demo",
        RPID:          "localhost",
        RPOrigins:     []string{"http://localhost:8080"},
        
        // Authenticator Selection Criteria - equivalent to authenticatorSelection in JS
        AuthenticatorSelection: protocol.AuthenticatorSelection{
            RequireResidentKey: protocol.ResidentKeyRequired(),  // Equivalent to residentKey: 'required'
            UserVerification:   protocol.VerificationDiscouraged, // Equivalent to userVerification: 'discouraged'
        },
    }

	// Create and return a new WebAuthn instance
	return webauthn.New(config)
}