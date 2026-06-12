package blacklist

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type BlacklistEntry struct {
	BlockedUntil time.Time `json:"blocked_until"`
}

type Blacklist struct {
	mu       sync.RWMutex
	filePath string
	entries  map[string]BlacklistEntry
}

func NewBlacklist(filePath string) (*Blacklist, error) {
	bl := &Blacklist{
		filePath: filePath,
		entries:  make(map[string]BlacklistEntry),
	}

	// Load existing from file if it exists
	if _, err := os.Stat(filePath); err == nil {
		data, err := os.ReadFile(filePath)
		if err == nil {
			var loaded map[string]BlacklistEntry
			if err := json.Unmarshal(data, &loaded); err == nil {
				bl.entries = loaded
			}
		}
	}

	return bl, nil
}

func (bl *Blacklist) Add(did string, ttl time.Duration) error {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	bl.entries[did] = BlacklistEntry{
		BlockedUntil: time.Now().Add(ttl),
	}

	return bl.save()
}

func (bl *Blacklist) IsBlacklisted(did string) bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	entry, exists := bl.entries[did]
	if !exists {
		return false
	}

	if time.Now().After(entry.BlockedUntil) {
		// Clean up expired entry in a goroutine
		go bl.Remove(did)
		return false
	}

	return true
}

func (bl *Blacklist) Remove(did string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	delete(bl.entries, did)
	_ = bl.save()
}

func (bl *Blacklist) save() error {
	data, err := json.MarshalIndent(bl.entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(bl.filePath, data, 0644)
}
