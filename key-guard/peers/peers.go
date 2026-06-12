package peers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type PeerInfo struct {
	DID       string `json:"did"`
	PublicKey string `json:"public_key"` // Base64 encoded Ed25519 public key
	Endpoint  string `json:"endpoint"`   // HTTP address
	Revoked   bool   `json:"revoked"`
}

type PeersStore struct {
	mu       sync.RWMutex
	filePath string
	peers    map[string]PeerInfo
}

// NewPeersStore creates or loads a PeersStore from a JSON file.
func NewPeersStore(filePath string) (*PeersStore, error) {
	store := &PeersStore{
		filePath: filePath,
		peers:    make(map[string]PeerInfo),
	}

	// Ensure parent directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory for peers store: %w", err)
	}

	// Load file if it exists
	if _, err := os.Stat(filePath); err == nil {
		data, err := os.ReadFile(filePath)
		if err == nil {
			var loaded map[string]PeerInfo
			if err := json.Unmarshal(data, &loaded); err == nil {
				store.peers = loaded
			}
		}
	}

	return store, nil
}

// AddPeer registers or updates a peer in the store.
func (ps *PeersStore) AddPeer(info PeerInfo) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// If peer exists and was revoked, reject updates unless we explicit reset
	if existing, exists := ps.peers[info.DID]; exists && existing.Revoked {
		return fmt.Errorf("cannot update revoked peer: %s", info.DID)
	}

	ps.peers[info.DID] = info
	return ps.save()
}

// ResolvePeer returns resolved peer info.
func (ps *PeersStore) ResolvePeer(did string) (PeerInfo, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	info, exists := ps.peers[did]
	if !exists {
		return PeerInfo{}, fmt.Errorf("peer not found: %s", did)
	}

	return info, nil
}

// RevokePeer marks a peer as revoked.
func (ps *PeersStore) RevokePeer(did string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	info, exists := ps.peers[did]
	if !exists {
		return fmt.Errorf("peer not found to revoke: %s", did)
	}

	info.Revoked = true
	ps.peers[did] = info
	return ps.save()
}

func (ps *PeersStore) save() error {
	data, err := json.MarshalIndent(ps.peers, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal peers data: %w", err)
	}
	return os.WriteFile(ps.filePath, data, 0644)
}
