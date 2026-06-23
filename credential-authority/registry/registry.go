package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"a2a-secure-net/credential-authority/credential"
)

// RevokedEntry represents a single revoked credential in the CRL.
type RevokedEntry struct {
	CredentialID string `json:"credentialId"`
	RevokedAt    string `json:"revokedAt"`
	Reason       string `json:"reason,omitempty"`
}

// StatusInfo represents the status of a single credential.
type StatusInfo struct {
	VCID      string `json:"vcId"`
	Status    string `json:"status"` // "valid", "revoked", "not_found"
	IssuedAt  string `json:"issuedAt,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// registryData is the on-disk format for JSON serialization.
type registryData struct {
	Issued []*credential.VerifiableCredential `json:"issued"`
	CRL    []RevokedEntry                     `json:"crl"`
}

// Registry holds all issued credentials and the Certificate Revocation List.
type Registry struct {
	mu     sync.RWMutex
	path   string
	issued []*credential.VerifiableCredential
	crl    []RevokedEntry
}

// LoadOrCreate loads a registry from disk or creates a new one.
func LoadOrCreate(path string) (*Registry, error) {
	r := &Registry{
		path:   path,
		issued: []*credential.VerifiableCredential{},
		crl:    []RevokedEntry{},
	}

	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read registry: %w", err)
		}
		var rd registryData
		if err := json.Unmarshal(data, &rd); err != nil {
			return nil, fmt.Errorf("failed to parse registry: %w", err)
		}
		r.issued = rd.Issued
		r.crl = rd.CRL
	}

	return r, nil
}

// persist saves the registry state to disk.
func (r *Registry) persist() error {
	rd := registryData{
		Issued: r.issued,
		CRL:    r.crl,
	}
	data, err := json.MarshalIndent(rd, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal registry: %w", err)
	}
	return os.WriteFile(r.path, data, 0644)
}

// Add registers a newly issued credential.
func (r *Registry) Add(vc *credential.VerifiableCredential) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.issued = append(r.issued, vc)
	_ = r.persist()
}

// Revoke marks a credential as revoked and adds it to the CRL.
func (r *Registry) Revoke(credentialID, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, entry := range r.crl {
		if entry.CredentialID == credentialID {
			return fmt.Errorf("credential already revoked")
		}
	}

	r.crl = append(r.crl, RevokedEntry{
		CredentialID: credentialID,
		RevokedAt:    time.Now().UTC().Format(time.RFC3339),
		Reason:       reason,
	})

	return r.persist()
}

// IsRevoked checks whether a credential ID appears in the CRL.
func (r *Registry) IsRevoked(credentialID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, entry := range r.crl {
		if entry.CredentialID == credentialID {
			return true
		}
	}
	return false
}

// GetCRL returns a copy of the current Certificate Revocation List.
func (r *Registry) GetCRL() []RevokedEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]RevokedEntry, len(r.crl))
	copy(result, r.crl)
	return result
}

// FindByAgentDID returns the latest valid credential for an agent DID.
func (r *Registry) FindByAgentDID(agentDID string) *credential.VerifiableCredential {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// Search from newest to oldest
	for i := len(r.issued) - 1; i >= 0; i-- {
		vc := r.issued[i]
		if vc.CredentialSubject.ID == agentDID {
			if !r.isRevokedLocked(vc.ID) {
				return vc
			}
		}
	}
	return nil
}

func (r *Registry) isRevokedLocked(credentialID string) bool {
	for _, entry := range r.crl {
		if entry.CredentialID == credentialID {
			return true
		}
	}
	return false
}

// IssuedCredentialInfo is a summary of an issued credential for listing.
type IssuedCredentialInfo struct {
	VCID      string `json:"vcId"`
	AgentDID  string `json:"agentDID"`
	AgentName string `json:"agentName"`
	IssuedAt  string `json:"issuedAt"`
	ExpiresAt string `json:"expiresAt"`
	Revoked   bool   `json:"revoked"`
}

// ListIssued returns summary info for all issued credentials.
func (r *Registry) ListIssued() []IssuedCredentialInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]IssuedCredentialInfo, len(r.issued))
	for i, vc := range r.issued {
		revoked := r.isRevokedLocked(vc.ID)
		result[i] = IssuedCredentialInfo{
			VCID:      vc.ID,
			AgentDID:  vc.CredentialSubject.ID,
			AgentName: vc.CredentialSubject.AgentName,
			IssuedAt:  vc.IssuanceDate,
			ExpiresAt: vc.ExpirationDate,
			Revoked:   revoked,
		}
	}
	return result
}

// TotalIssued returns the count of issued credentials.
func (r *Registry) TotalIssued() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.issued)
}

// TotalRevoked returns the count of revoked credentials.
func (r *Registry) TotalRevoked() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.crl)
}

// Reset clears all issued credentials and the CRL, then persists.
func (r *Registry) Reset() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.issued = []*credential.VerifiableCredential{}
	r.crl = []RevokedEntry{}
	return r.persist()
}

// GetStatus returns the status of a specific credential by ID.
func (r *Registry) GetStatus(vcID string) (*StatusInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, entry := range r.crl {
		if entry.CredentialID == vcID {
			return &StatusInfo{
				VCID:   vcID,
				Status: "revoked",
			}, nil
		}
	}

	for _, vc := range r.issued {
		if vc.ID == vcID {
			return &StatusInfo{
				VCID:      vcID,
				Status:    "valid",
				IssuedAt:  vc.IssuanceDate,
				ExpiresAt: vc.ExpirationDate,
			}, nil
		}
	}

	return &StatusInfo{
		VCID:   vcID,
		Status: "not_found",
	}, nil
}
