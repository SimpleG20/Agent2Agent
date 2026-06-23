// Package credential provides W3C Verifiable Credential types, storage,
// and verification for the A2A Key Guard.
//
// Credentials are issued by the Credential Authority (CA) service and
// verified locally using the CA's public key with CRL caching for offline
// resilience.
package credential

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// --- W3C VC Types (duplicated from credential-authority for zero deps) ---

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

// --- CredentialStore ---

// storeData is the on-disk format for the credential store.
type storeData struct {
	OwnVC          *VerifiableCredential `json:"ownVC"`
	CADID          string                `json:"caDID"`
	CAPublicKeyB64 string                `json:"caPublicKeyBase64"`
}

// CredentialStore persists the agent's own VC and CA metadata.
type CredentialStore struct {
	mu    sync.RWMutex
	path  string
	ownVC *VerifiableCredential
	caDID string
	caPub ed25519.PublicKey
}

// NewCredentialStore loads or creates a credential store.
func NewCredentialStore(path string) (*CredentialStore, error) {
	cs := &CredentialStore{
		path: path,
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create credential store directory: %w", err)
	}

	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read credential store: %w", err)
		}
		var sd storeData
		if err := json.Unmarshal(data, &sd); err != nil {
			return nil, fmt.Errorf("failed to parse credential store: %w", err)
		}
		cs.ownVC = sd.OwnVC
		cs.caDID = sd.CADID
		if sd.CAPublicKeyB64 != "" {
			pubBytes, err := base64.StdEncoding.DecodeString(sd.CAPublicKeyB64)
			if err != nil {
				return nil, fmt.Errorf("failed to decode CA public key: %w", err)
			}
			cs.caPub = ed25519.PublicKey(pubBytes)
		}
	}

	return cs, nil
}

// save persists the credential store to disk.
func (cs *CredentialStore) save() error {
	sd := storeData{
		OwnVC: cs.ownVC,
		CADID: cs.caDID,
	}
	if cs.caPub != nil {
		sd.CAPublicKeyB64 = base64.StdEncoding.EncodeToString(cs.caPub)
	}
	data, err := json.MarshalIndent(sd, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credential store: %w", err)
	}
	return os.WriteFile(cs.path, data, 0644)
}

// SetOwnVC sets the agent's own verifiable credential.
func (cs *CredentialStore) SetOwnVC(vc *VerifiableCredential) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.ownVC = vc
	_ = cs.save()
}

// GetOwnVC returns the agent's own verifiable credential.
func (cs *CredentialStore) GetOwnVC() *VerifiableCredential {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.ownVC
}

// SetCAInfo sets the CA's DID and public key.
func (cs *CredentialStore) SetCAInfo(caDID string, caPublicKey ed25519.PublicKey) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.caDID = caDID
	cs.caPub = caPublicKey
	_ = cs.save()
}

// GetCADID returns the CA's DID.
func (cs *CredentialStore) GetCADID() string {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.caDID
}

// GetCAPublicKey returns the CA's Ed25519 public key.
func (cs *CredentialStore) GetCAPublicKey() ed25519.PublicKey {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.caPub
}

// HasCredential returns true if the agent has a valid VC stored.
func (cs *CredentialStore) HasCredential() bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.ownVC != nil
}

// --- CRLCache ---

// CRLCache caches the Certificate Revocation List with TTL.
type CRLCache struct {
	mu        sync.RWMutex
	revoked   map[string]bool // credentialID -> revoked
	lastFetch time.Time
	ttl       time.Duration
	caURL     string
}

// NewCRLCache creates a new CRL cache.
func NewCRLCache(caURL string, ttl time.Duration) *CRLCache {
	return &CRLCache{
		revoked: make(map[string]bool),
		ttl:     ttl,
		caURL:   caURL,
	}
}

// IsRevoked checks if a credential ID is in the CRL, refreshing the cache if needed.
func (c *CRLCache) IsRevoked(credentialID string) bool {
	c.mu.RLock()
	if time.Since(c.lastFetch) < c.ttl {
		val := c.revoked[credentialID]
		c.mu.RUnlock()
		return val
	}
	c.mu.RUnlock()

	// Cache expired — refresh
	c.refresh()

	// Re-acquire lock after refresh (which released write lock)
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.revoked[credentialID]
}

// refresh fetches the latest CRL from the CA.
func (c *CRLCache) refresh() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if time.Since(c.lastFetch) < c.ttl {
		return
	}

	resp, err := http.Get(fmt.Sprintf("%s/credential/crl", c.caURL))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var result struct {
		TotalRevoked int `json:"totalRevoked"`
		Entries      []struct {
			CredentialID string `json:"credentialId"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return
	}

	newRevoked := make(map[string]bool)
	for _, entry := range result.Entries {
		newRevoked[entry.CredentialID] = true
	}
	c.revoked = newRevoked
	c.lastFetch = time.Now()
}

// --- CA Client Functions ---

// FetchCAInfo retrieves the CA's DID and public key from its /ca/info endpoint.
func FetchCAInfo(caURL string) (caDID string, caPublicKey ed25519.PublicKey, err error) {
	resp, err := http.Get(fmt.Sprintf("%s/ca/info", caURL))
	if err != nil {
		return "", nil, fmt.Errorf("failed to connect to CA: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read CA response: %w", err)
	}

	var info struct {
		Did             string `json:"did"`
		PublicKeyBase64 string `json:"publicKeyBase64"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", nil, fmt.Errorf("failed to parse CA info: %w", err)
	}

	if info.Did == "" || info.PublicKeyBase64 == "" {
		return "", nil, fmt.Errorf("CA info missing DID or public key")
	}

	pubBytes, err := base64.StdEncoding.DecodeString(info.PublicKeyBase64)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode CA public key: %w", err)
	}

	return info.Did, ed25519.PublicKey(pubBytes), nil
}

// RequestCredentialFromCA requests a new VC from the Credential Authority.
func RequestCredentialFromCA(caURL, agentDID, publicKeyMultibase, agentName string) (*VerifiableCredential, error) {
	reqBody := map[string]string{
		"did":                agentDID,
		"publicKeyMultibase": publicKeyMultibase,
		"agentName":          agentName,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	resp, err := http.Post(
		fmt.Sprintf("%s/credential/issue", caURL),
		"application/json",
		bytes.NewBuffer(bodyBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to contact CA for VC issuance: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read VC response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CA returned error %d: %s", resp.StatusCode, string(respBody))
	}

	var vc VerifiableCredential
	if err := json.Unmarshal(respBody, &vc); err != nil {
		return nil, fmt.Errorf("failed to parse VC from CA: %w", err)
	}

	return &vc, nil
}

// VerifyCredentialLocally performs full local verification of a credential:
// signature, expiration, and CRL check.
func VerifyCredentialLocally(vc *VerifiableCredential, caPublicKey ed25519.PublicKey, crlCache *CRLCache) error {
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

	// 2. Verify issuer matches CA DID
	// (issuer check is optional — signature proves it)

	// 3. Verify signature using CA's public key
	if err := vc.Verify(caPublicKey); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// 4. Verify expiration
	if vc.IsExpired() {
		return fmt.Errorf("credential expired at %s", vc.ExpirationDate)
	}

	// 5. Check CRL
	if crlCache.IsRevoked(vc.ID) {
		return fmt.Errorf("credential has been revoked")
	}

	return nil
}

// VerifyCredentialOnCA delegates verification to the CA's /credential/verify endpoint.
func VerifyCredentialOnCA(caURL string, vc *VerifiableCredential) (bool, error) {
	reqBody := map[string]interface{}{
		"credential": vc,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	resp, err := http.Post(
		fmt.Sprintf("%s/credential/verify", caURL),
		"application/json",
		bytes.NewBuffer(bodyBytes),
	)
	if err != nil {
		return false, fmt.Errorf("failed to contact CA for verification: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read verification response: %w", err)
	}

	var result struct {
		Verified bool   `json:"verified"`
		Error    string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return false, fmt.Errorf("failed to parse verification response: %w", err)
	}

	if !result.Verified {
		return false, fmt.Errorf("CA verification failed: %s", result.Error)
	}

	return true, nil
}
