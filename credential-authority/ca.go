package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"a2a-secure-net/credential-authority/base58"
	"a2a-secure-net/credential-authority/credential"
	"a2a-secure-net/credential-authority/registry"
)

// CredentialAuthority is the central trust anchor for the A2A network.
// It issues, verifies, and revokes W3C Verifiable Credentials for agents.
type CredentialAuthority struct {
	mu         sync.RWMutex
	name       string
	did        string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	reg        *registry.Registry
	datadir    string
}

// NewCredentialAuthority initializes a CA, loading or generating its root key.
func NewCredentialAuthority(name string, datadir string) (*CredentialAuthority, error) {
	if err := os.MkdirAll(datadir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create datadir %s: %w", datadir, err)
	}

	privKey, err := loadOrGenerateRootKey(datadir)
	if err != nil {
		return nil, fmt.Errorf("failed to load/generate root key: %w", err)
	}

	pubKey := privKey.Public().(ed25519.PublicKey)
	did := base58.GenerateDIDKey(pubKey)

	reg, err := registry.LoadOrCreate(filepath.Join(datadir, "registry.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to load registry: %w", err)
	}

	return &CredentialAuthority{
		name:       name,
		did:        did,
		privateKey: privKey,
		publicKey:  pubKey,
		reg:        reg,
		datadir:    datadir,
	}, nil
}

// DID returns the CA's own did:key: identifier.
func (ca *CredentialAuthority) DID() string {
	return ca.did
}

// PublicKey returns the CA's Ed25519 public key.
func (ca *CredentialAuthority) PublicKey() ed25519.PublicKey {
	return ca.publicKey
}

// Name returns the CA's human-readable name.
func (ca *CredentialAuthority) Name() string {
	return ca.name
}

// TotalIssued returns the total number of credentials issued by this CA.
func (ca *CredentialAuthority) TotalIssued() int {
	return ca.reg.TotalIssued()
}

// TotalRevoked returns the total number of revoked credentials.
func (ca *CredentialAuthority) TotalRevoked() int {
	return ca.reg.TotalRevoked()
}

// IssueCredential issues a new W3C Verifiable Credential for an agent.
func (ca *CredentialAuthority) IssueCredential(agentDID, publicKeyMultibase, agentName string) (*credential.VerifiableCredential, error) {
	if agentDID == "" || publicKeyMultibase == "" || agentName == "" {
		return nil, fmt.Errorf("missing required fields: did, publicKeyMultibase, agentName")
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Reuse existing valid credential if one exists
	if existing := ca.reg.FindByAgentDID(agentDID); existing != nil {
		expDate, err := time.Parse(time.RFC3339, existing.ExpirationDate)
		if err == nil && time.Now().Before(expDate) {
			return existing, nil
		}
	}

	credID := fmt.Sprintf("vc:a2a:ca:%s-%d", agentName, time.Now().UnixNano())

	subject := credential.CredentialSubject{
		ID:                 agentDID,
		PublicKeyMultibase: publicKeyMultibase,
		AgentName:          agentName,
		AgentRole:          "standard",
		TrustLevel:         "trusted",
		Capabilities:       []string{"messaging", "task-execution"},
	}

	vc := credential.NewVerifiableCredential(credID, ca.did, subject, 180)

	if err := vc.Sign(ca.did, ca.privateKey); err != nil {
		return nil, fmt.Errorf("failed to sign credential: %w", err)
	}

	ca.reg.Add(vc)
	return vc, nil
}

// VerifyCredential verifies a credential: type, signature, expiration, and CRL.
func (ca *CredentialAuthority) VerifyCredential(vc *credential.VerifiableCredential) error {
	// 1. Verify type contains VerifiableCredential
	hasType := false
	for _, t := range vc.Type {
		if t == "VerifiableCredential" {
			hasType = true
			break
		}
	}
	if !hasType {
		return fmt.Errorf("invalid credential type: missing VerifiableCredential")
	}

	// 2. Verify signature using CA's public key
	if err := vc.Verify(ca.publicKey); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// 3. Verify expiration
	if vc.IsExpired() {
		return fmt.Errorf("credential expired at %s", vc.ExpirationDate)
	}

	// 4. Check CRL
	if ca.reg.IsRevoked(vc.ID) {
		return fmt.Errorf("credential has been revoked")
	}

	return nil
}

// RevokeCredential revokes a credential by its ID.
func (ca *CredentialAuthority) RevokeCredential(credentialID, reason string) error {
	return ca.reg.Revoke(credentialID, reason)
}

// GetCRL returns the current Certificate Revocation List.
func (ca *CredentialAuthority) GetCRL() []registry.RevokedEntry {
	return ca.reg.GetCRL()
}

// GetCredentialStatus returns the status of a specific credential.
func (ca *CredentialAuthority) GetCredentialStatus(vcID string) (*registry.StatusInfo, error) {
	return ca.reg.GetStatus(vcID)
}

// loadOrGenerateRootKey loads an existing Ed25519 root key or generates a new one.
func loadOrGenerateRootKey(datadir string) (ed25519.PrivateKey, error) {
	keyPath := filepath.Join(datadir, "root_key")
	privPath := keyPath + ".priv"
	pubPath := keyPath + ".pub"

	if _, err := os.Stat(privPath); err == nil {
		privData, err := os.ReadFile(privPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key: %w", err)
		}
		decoded, err := base64.StdEncoding.DecodeString(string(privData))
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key: %w", err)
		}
		return ed25519.PrivateKey(decoded), nil
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate root key: %w", err)
	}

	privEncoded := base64.StdEncoding.EncodeToString(privKey)
	if err := os.WriteFile(privPath, []byte(privEncoded), 0600); err != nil {
		return nil, fmt.Errorf("failed to save private key: %w", err)
	}

	pubEncoded := base64.StdEncoding.EncodeToString(pubKey)
	if err := os.WriteFile(pubPath, []byte(pubEncoded), 0644); err != nil {
		return nil, fmt.Errorf("failed to save public key: %w", err)
	}

	return privKey, nil
}
