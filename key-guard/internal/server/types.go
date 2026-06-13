// Package server provides the HTTP API for the Key Guard service.
package server

import (
	"encoding/json"
	"net/http"
)

// SigningIntent represents a signing request from an agent.
type SigningIntent struct {
	Action    string          `json:"action"`
	Payload   json.RawMessage `json:"payload"`
	AgentID   string          `json:"agent_id"`
	Timestamp int64           `json:"timestamp"`
	Nonce     string          `json:"nonce"`
}

// SignRequest is the full request body for POST /v1/sign.
type SignRequest struct {
	Action    string          `json:"action"`
	Payload   json.RawMessage `json:"payload"`
	AgentID   string          `json:"agent_id"`
	Timestamp int64           `json:"timestamp"`
	Nonce     string          `json:"nonce"`
}

// SignResponse is the response for POST /v1/sign.
type SignResponse struct {
	Status    string `json:"status"`
	RequestID string `json:"request_id,omitempty"`
	DID       string `json:"did,omitempty"`
	Signature string `json:"signature,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// SigningError represents a rejected signing intent.
type SigningError struct {
	HTTPStatus int
	Reason     string
}

func (e *SigningError) Error() string {
	return e.Reason
}

// DIDResponse is the response for GET /v1/did.
type DIDResponse struct {
	DID             string `json:"did"`
	PublicKeyBase58 string `json:"public_key_base58"`
	KeyType         string `json:"key_type"`
}

// HealthResponse is the response for GET /v1/health.
type HealthResponse struct {
	Status         string `json:"status"`
	RedisConnected bool   `json:"redis_connected"`
	KeyLoaded      bool   `json:"key_loaded"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
}

// ErrorResponse is a generic error envelope.
type ErrorResponse struct {
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	RequestID string `json:"request_id,omitempty"`
}

// RevocationEntry is a single active revocation in the list response.
type RevocationEntry struct {
	DID        string `json:"did"`
	Status     string `json:"status"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// RevocationListResponse is the response for GET /v1/revocations.
type RevocationListResponse struct {
	Status      string            `json:"status"`
	Revocations []RevocationEntry `json:"revocations"`
}

// RevokeRequest is the request body for POST /v1/revoke.
type RevokeRequest struct {
	DID        string `json:"did"`
	Status     string `json:"status"`       // "revoked" or "suspended"
	TTLSeconds int    `json:"ttl_seconds"`  // 0 = default
}

// RevokeResponse is the response for POST /v1/revoke and /v1/restore.
type RevokeResponse struct {
	Status    string `json:"status"`
	DID       string `json:"did"`
	RequestID string `json:"request_id,omitempty"`
}

// writeJSON marshals v and writes it as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, reason, requestID string) {
	writeJSON(w, status, ErrorResponse{
		Status:    "error",
		Reason:    reason,
		RequestID: requestID,
	})
}
