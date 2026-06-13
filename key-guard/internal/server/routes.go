package server

import (
	"crypto/ed25519"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/mr-tron/base58"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stumgart/a2a/key-guard/internal/crypto"
	"github.com/stumgart/a2a/key-guard/internal/storage"
	"github.com/stumgart/a2a/key-guard/internal/validation"
)

// KeyGuardServer is the HTTP server for the Key Guard service.
type KeyGuardServer struct {
	router          *chi.Mux
	privKey         ed25519.PrivateKey
	pubKey          ed25519.PublicKey
	serviceDID      string
	revocationStore *storage.RevocationStore
	nonceStore      *storage.NonceStore
	budgetStore     *validation.BudgetStore
	startTime       time.Time
}

// NewKeyGuardServer creates a new KeyGuardServer with all dependencies wired.
func NewKeyGuardServer(
	privKey ed25519.PrivateKey,
	revocationStore *storage.RevocationStore,
	nonceStore *storage.NonceStore,
	budgetStore *validation.BudgetStore,
) (*KeyGuardServer, error) {

	pubKey := privKey.Public().(ed25519.PublicKey)
	serviceDID, err := crypto.DIDFromPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	srv := &KeyGuardServer{
		privKey:         privKey,
		pubKey:          pubKey,
		serviceDID:      serviceDID,
		revocationStore: revocationStore,
		nonceStore:      nonceStore,
		budgetStore:     budgetStore,
		startTime:       time.Now(),
	}

	srv.router = chi.NewRouter()
	srv.registerMiddleware()
	srv.registerRoutes()

	return srv, nil
}

func (s *KeyGuardServer) registerMiddleware() {
	s.router.Use(RequestIDMiddleware)
	s.router.Use(LoggingMiddleware)
	s.router.Use(MetricsMiddleware)
	s.router.Use(RecoveryMiddleware)
	s.router.Use(middleware.Timeout(30 * time.Second))
}

func (s *KeyGuardServer) registerRoutes() {
	s.router.Get("/v1/health", s.handleHealth)
	s.router.Get("/v1/did", s.handleGetDID)
	s.router.Post("/v1/sign", s.handleSign)
	s.router.Get("/v1/revocations", s.handleListRevocations)
	s.router.Post("/v1/revoke", s.handleRevoke)
	s.router.Post("/v1/restore", s.handleRestore)
	s.router.Get("/metrics", promhttp.Handler().ServeHTTP)
}

// Handler returns the HTTP handler for the server.
func (s *KeyGuardServer) Handler() http.Handler {
	return s.router
}

// handleHealth returns the health status of the service.
func (s *KeyGuardServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	keyLoaded := s.privKey != nil && len(s.pubKey) > 0

	redisConnected := true
	if _, err := s.revocationStore.CheckRevoked(r.Context(), "__healthcheck__"); err != nil {
		redisConnected = false
	}

	status := "ok"
	if !redisConnected || !keyLoaded {
		status = "degraded"
	}

	writeJSON(w, http.StatusOK, HealthResponse{
		Status:         status,
		RedisConnected: redisConnected,
		KeyLoaded:      keyLoaded,
		UptimeSeconds:  int64(time.Since(s.startTime).Seconds()),
	})
}

// handleGetDID returns the service's public DID.
func (s *KeyGuardServer) handleGetDID(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, DIDResponse{
		DID:             s.serviceDID,
		PublicKeyBase58: base58.Encode(s.pubKey),
		KeyType:         "Ed25519",
	})
}

// handleSign processes a signing intent.
func (s *KeyGuardServer) handleSign(w http.ResponseWriter, r *http.Request) {
	reqID := getRequestID(r.Context())

	// Parse request body
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[%s] invalid JSON body: %v", reqID, err)
		signTotal.WithLabelValues("invalid_json").Inc()
		writeError(w, http.StatusBadRequest, "invalid_request_body", reqID)
		return
	}

	// Marshal the full request as body for schema validation
	body, err := json.Marshal(req)
	if err != nil {
		log.Printf("[%s] marshal error: %v", reqID, err)
		writeError(w, http.StatusInternalServerError, "internal_error", reqID)
		return
	}

	// --- Validation pipeline ---

	// 1. JSON Schema validation
	intent, vr := validation.ValidateIntent(body)
	if !vr.Valid {
		log.Printf("[%s] schema validation failed: %s", reqID, vr.Reason)
		signTotal.WithLabelValues("invalid_schema").Inc()
		writeError(w, http.StatusBadRequest, "invalid_schema", reqID)
		return
	}

	// 2. Timestamp validation
	vr = validation.ValidateTimestamp(intent.Timestamp, time.Now())
	if !vr.Valid {
		log.Printf("[%s] timestamp validation failed: %s", reqID, vr.Reason)
		signTotal.WithLabelValues("expired_timestamp").Inc()
		writeError(w, http.StatusBadRequest, "expired_timestamp", reqID)
		return
	}

	// 3. Nonce replay protection
	if !s.nonceStore.CheckAndSet(intent.Nonce) {
		log.Printf("[%s] nonce replay detected: %s", reqID, intent.Nonce)
		signTotal.WithLabelValues("reused_nonce").Inc()
		writeError(w, http.StatusBadRequest, "reused_nonce", reqID)
		return
	}

	// 4. Policy engine
	vr = validation.RunPolicies(intent, validation.DefaultPolicies)
	if !vr.Valid {
		log.Printf("[%s] policy rejected: %s", reqID, vr.Reason)
		signTotal.WithLabelValues("policy_rejected").Inc()
		writeError(w, http.StatusForbidden, "policy_rejected: "+vr.Reason, reqID)
		return
	}

	// 5. Budget/rate limit check
	allowed, reason := s.budgetStore.Allow(intent.AgentID, time.Now())
	if !allowed {
		log.Printf("[%s] budget exceeded for agent %s: %s", reqID, intent.AgentID, reason)
		signTotal.WithLabelValues("rate_limit_exceeded").Inc()
		writeError(w, http.StatusTooManyRequests, "rate_limit_exceeded", reqID)
		return
	}

	// 6. Recipient revocation check
	recipientDID := extractRecipientDID(intent)
	if recipientDID != "" {
		revoked, err := s.revocationStore.CheckRevoked(r.Context(), recipientDID)
		if err != nil {
			log.Printf("[%s] revocation check error for %s: %v", reqID, recipientDID, err)
			signTotal.WithLabelValues("revocation_check_error").Inc()
			writeError(w, http.StatusServiceUnavailable, "service_unavailable", reqID)
			return
		}
		if revoked {
			log.Printf("[%s] recipient %s is revoked", reqID, recipientDID)
			signTotal.WithLabelValues("recipient_revoked").Inc()
			writeError(w, http.StatusForbidden, "recipient_revoked", reqID)
			return
		}
	}

	// --- Sign the payload and build DIDComm envelope ---
	payloadBytes := []byte(intent.Payload)

	// Build DIDComm envelope (internally signs with Ed25519)
	envelope, err := crypto.BuildEnvelope(
		payloadBytes,
		s.privKey,
		s.serviceDID,
		recipientDID,
	)
	if err != nil {
		log.Printf("[%s] envelope build error: %v", reqID, err)
		signTotal.WithLabelValues("internal_error").Inc()
		writeError(w, http.StatusInternalServerError, "internal_error", reqID)
		return
	}

	log.Printf("[%s] signed intent for agent=%s action=%s", reqID, intent.AgentID, intent.Action)
	signTotal.WithLabelValues("signed").Inc()

	writeJSON(w, http.StatusOK, SignResponse{
		Status:    "signed",
		RequestID: reqID,
		DID:       s.serviceDID,
		Signature: envelope.Signature,
	})
}

// extractRecipientDID attempts to extract recipient_did from the payload.
func extractRecipientDID(intent *validation.SigningIntent) string {
	if intent.Payload == nil {
		return ""
	}
	var payload struct {
		RecipientDID string `json:"recipient_did"`
	}
	if err := json.Unmarshal(intent.Payload, &payload); err != nil {
		return ""
	}
	return payload.RecipientDID
}

// handleListRevocations returns all active revocations from Redis.
func (s *KeyGuardServer) handleListRevocations(w http.ResponseWriter, r *http.Request) {
	entries, err := s.revocationStore.ListRevocations(r.Context())
	if err != nil {
		log.Printf("[list-revocations] error: %v", err)
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", getRequestID(r.Context()))
		return
	}
	resp := RevocationListResponse{
		Status:      "ok",
		Revocations: make([]RevocationEntry, 0, len(entries)),
	}
	for _, e := range entries {
		resp.Revocations = append(resp.Revocations, RevocationEntry{
			DID:        e.DID,
			Status:     string(e.Status),
			TTLSeconds: int(e.TTL.Seconds()),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRevoke marks a DID as revoked or suspended.
func (s *KeyGuardServer) handleRevoke(w http.ResponseWriter, r *http.Request) {
	reqID := getRequestID(r.Context())

	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_body", reqID)
		return
	}
	if req.DID == "" {
		writeError(w, http.StatusBadRequest, "did_required", reqID)
		return
	}

	status := storage.StatusRevoked
	switch req.Status {
	case "suspended":
		status = storage.StatusSuspended
	case "revoked", "":
		status = storage.StatusRevoked
	default:
		writeError(w, http.StatusBadRequest, "invalid_status", reqID)
		return
	}

	if err := s.revocationStore.RevokeWithTTL(r.Context(), req.DID, status, req.TTLSeconds); err != nil {
		log.Printf("[%s] revoke error: %v", reqID, err)
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", reqID)
		return
	}

	log.Printf("[%s] revoked did=%s status=%s ttl=%d", reqID, req.DID, status, req.TTLSeconds)
	writeJSON(w, http.StatusOK, RevokeResponse{
		Status:    "revoked",
		DID:       req.DID,
		RequestID: reqID,
	})
}

// handleRestore clears a revocation for a DID.
func (s *KeyGuardServer) handleRestore(w http.ResponseWriter, r *http.Request) {
	reqID := getRequestID(r.Context())

	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_body", reqID)
		return
	}
	if req.DID == "" {
		writeError(w, http.StatusBadRequest, "did_required", reqID)
		return
	}

	if err := s.revocationStore.ClearRevocation(r.Context(), req.DID); err != nil {
		log.Printf("[%s] restore error: %v", reqID, err)
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", reqID)
		return
	}

	log.Printf("[%s] restored did=%s", reqID, req.DID)
	writeJSON(w, http.StatusOK, RevokeResponse{
		Status:    "restored",
		DID:       req.DID,
		RequestID: reqID,
	})
}
