package credential

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// VerifiableCredential represents a W3C Verifiable Credential.
type VerifiableCredential struct {
	Context           []string          `json:"@context"`
	ID                string            `json:"id"`
	Type              []string          `json:"type"`
	Issuer            string            `json:"issuer"`
	IssuanceDate      string            `json:"issuanceDate"`
	ExpirationDate    string            `json:"expirationDate"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
	Proof             *Ed25519Proof     `json:"proof,omitempty"`
}

// CredentialSubject represents the subject of a Verifiable Credential.
type CredentialSubject struct {
	ID                 string   `json:"id"`
	PublicKeyMultibase string   `json:"publicKeyMultibase"`
	AgentName          string   `json:"agentName"`
	AgentRole          string   `json:"agentRole"`
	TrustLevel         string   `json:"trustLevel"`
	Capabilities       []string `json:"capabilities,omitempty"`
}

// Ed25519Proof represents an Ed25519Signature2020 proof.
type Ed25519Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	ProofValue         string `json:"proofValue"`
}

// NewVerifiableCredential creates a new VC struct without proof.
func NewVerifiableCredential(id, issuerDID string, subject CredentialSubject, validityDays int) *VerifiableCredential {
	now := time.Now().UTC()
	return &VerifiableCredential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		ID:                id,
		Type:              []string{"VerifiableCredential", "AgentCredential"},
		Issuer:            issuerDID,
		IssuanceDate:      now.Format(time.RFC3339),
		ExpirationDate:    now.AddDate(0, 0, validityDays).Format(time.RFC3339),
		CredentialSubject: subject,
	}
}

// Sign adds an Ed25519Signature2020 proof to the credential.
func (vc *VerifiableCredential) Sign(signerDID string, privateKey ed25519.PrivateKey) error {
	signingVC := *vc
	signingVC.Proof = nil

	data, err := json.Marshal(signingVC)
	if err != nil {
		return fmt.Errorf("failed to marshal VC for signing: %w", err)
	}

	signature := ed25519.Sign(privateKey, data)

	vc.Proof = &Ed25519Proof{
		Type:               "Ed25519Signature2020",
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: signerDID + "#key-1",
		ProofPurpose:       "assertionMethod",
		ProofValue:         base64.RawURLEncoding.EncodeToString(signature),
	}

	return nil
}

// Verify checks the Ed25519 signature of the credential using the given public key.
func (vc *VerifiableCredential) Verify(publicKey ed25519.PublicKey) error {
	if vc.Proof == nil {
		return fmt.Errorf("credential has no proof")
	}

	signingVC := *vc
	signingVC.Proof = nil

	data, err := json.Marshal(signingVC)
	if err != nil {
		return fmt.Errorf("failed to marshal VC for verification: %w", err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(vc.Proof.ProofValue)
	if err != nil {
		return fmt.Errorf("failed to decode proof value: %w", err)
	}

	if !ed25519.Verify(publicKey, data, sigBytes) {
		return fmt.Errorf("invalid credential signature")
	}

	return nil
}

// IsExpired checks whether the credential has passed its expiration date.
func (vc *VerifiableCredential) IsExpired() bool {
	expDate, err := time.Parse(time.RFC3339, vc.ExpirationDate)
	if err != nil {
		return true
	}
	return time.Now().After(expDate)
}
