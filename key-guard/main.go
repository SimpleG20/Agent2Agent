package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"a2a-secure-net/key-guard/blacklist"
	"a2a-secure-net/key-guard/crypto"
	"a2a-secure-net/key-guard/didcomm"
	"a2a-secure-net/key-guard/peers"
	"a2a-secure-net/key-guard/rules"
)

type Config struct {
	Port      string
	AgentName string
	DID       string
	Endpoint  string
	DataDir   string
}

type KeyGuardApp struct {
	cfg        Config
	privKey    ed25519.PrivateKey
	pubKey     ed25519.PublicKey
	peersStore *peers.PeersStore
	blacklist  *blacklist.Blacklist
	inbox      []*didcomm.DIDCommMessage
	inboxMu    sync.Mutex
}

func main() {
	port := flag.String("port", "8001", "Port to run Key Guard server on")
	agentName := flag.String("name", "alfa", "Name of the agent (alfa or beta)")
	endpoint := flag.String("endpoint", "http://localhost:8001", "P2P public endpoint for this key guard")
	dataDir := flag.String("datadir", "./data", "Directory to store keys, peers and blacklist cache")
	flag.Parse()

	cfg := Config{
		Port:      *port,
		AgentName: *agentName,
		DID:       "did:custom:" + *agentName,
		Endpoint:  *endpoint,
		DataDir:   *dataDir,
	}

	app, err := InitializeApp(cfg)
	if err != nil {
		log.Fatalf("Initialization failed: %v", err)
	}

	log.Printf("[%s] Initialized Key Guard for %s (DID: %s)", cfg.AgentName, cfg.AgentName, cfg.DID)

	// Setup Server
	mux := http.NewServeMux()
	mux.HandleFunc("/sign-message", app.handleSignMessage)
	mux.HandleFunc("/send-message", app.handleSendMessage)
	mux.HandleFunc("/receive-message", app.handleReceiveMessage)
	mux.HandleFunc("/blacklist", app.handleBlacklist)
	mux.HandleFunc("/inbox", app.handleInbox)
	mux.HandleFunc("/resolve", app.handleResolve)
	
	// P2P Handshake Endpoints
	mux.HandleFunc("/handshake", app.handleHandshake)
	mux.HandleFunc("/handshake-peer", app.handleHandshakePeer)

	serverAddr := ":" + cfg.Port
	log.Printf("[%s] Key Guard HTTP server listening on %s (P2P endpoint: %s)", cfg.AgentName, serverAddr, cfg.Endpoint)
	if err := http.ListenAndServe(serverAddr, mux); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}

func InitializeApp(cfg Config) (*KeyGuardApp, error) {
	// 1. Create Data Directories
	keysDir := filepath.Join(cfg.DataDir, cfg.AgentName, "keys")
	privKeyPath := filepath.Join(keysDir, "private.key")
	pubKeyPath := filepath.Join(keysDir, "public.key")

	var pub ed25519.PublicKey
	var priv ed25519.PrivateKey
	var err error

	// Load or generate Ed25519 keys
	if _, errPriv := os.Stat(privKeyPath); errPriv == nil {
		log.Printf("[%s] Loading existing Ed25519 keys from disk...", cfg.AgentName)
		privBytes, err := crypto.LoadKeyFromFile(privKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}
		priv = ed25519.PrivateKey(privBytes)
		pubBytes, err := crypto.LoadKeyFromFile(pubKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load public key: %w", err)
		}
		pub = ed25519.PublicKey(pubBytes)
	} else {
		log.Printf("[%s] Generating new Ed25519 keys...", cfg.AgentName)
		pub, priv, err = crypto.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate keypair: %w", err)
		}
		if err := crypto.SaveKeyToFile(privKeyPath, priv); err != nil {
			return nil, fmt.Errorf("failed to save private key: %w", err)
		}
		if err := crypto.SaveKeyToFile(pubKeyPath, pub); err != nil {
			return nil, fmt.Errorf("failed to save public key: %w", err)
		}
	}

	// 2. Initialize local Peers Store
	peersFile := filepath.Join(cfg.DataDir, cfg.AgentName, "peers.json")
	peersStore, err := peers.NewPeersStore(peersFile)
	if err != nil {
		return nil, fmt.Errorf("failed to init peers store: %w", err)
	}

	// 3. Initialize Blacklist cache
	blFile := filepath.Join(cfg.DataDir, cfg.AgentName, "blacklist.json")
	bl, err := blacklist.NewBlacklist(blFile)
	if err != nil {
		return nil, fmt.Errorf("failed to init blacklist: %w", err)
	}

	return &KeyGuardApp{
		cfg:        cfg,
		privKey:    priv,
		pubKey:     pub,
		peersStore: peersStore,
		blacklist:  bl,
		inbox:      make([]*didcomm.DIDCommMessage, 0),
	}, nil
}

// REST HANDLERS

// handleHandshake (POST, P2P Public): Receives handshake from peer and registers it.
// Returns own DID info to complete mutual registration in one round-trip.
func (app *KeyGuardApp) handleHandshake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var peerInfo peers.PeerInfo
	if err := json.NewDecoder(r.Body).Decode(&peerInfo); err != nil {
		http.Error(w, "Invalid handshake payload", http.StatusBadRequest)
		return
	}

	log.Printf("[%s] Received handshake request from %s at %s", app.cfg.AgentName, peerInfo.DID, peerInfo.Endpoint)

	// Check if peer is blacklisted
	if app.blacklist.IsBlacklisted(peerInfo.DID) {
		log.Printf("[%s] Rejecting handshake request from blacklisted peer %s", app.cfg.AgentName, peerInfo.DID)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("cannot handshake with blacklisted peer: %s", peerInfo.DID)})
		return
	}

	// Save peer
	if err := app.peersStore.AddPeer(peerInfo); err != nil {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Respond with own DID information to achieve mutual trust
	pubKeyB64 := base64.StdEncoding.EncodeToString(app.pubKey)
	resp := peers.PeerInfo{
		DID:       app.cfg.DID,
		PublicKey: pubKeyB64,
		Endpoint:  app.cfg.Endpoint,
		Revoked:   false,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// handleHandshakePeer (POST, Internal): Commands the local Key Guard to initiate handshake with a target endpoint.
func (app *KeyGuardApp) handleHandshakePeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TargetEndpoint string `json:"target_endpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	pubKeyB64 := base64.StdEncoding.EncodeToString(app.pubKey)
	myInfo := peers.PeerInfo{
		DID:       app.cfg.DID,
		PublicKey: pubKeyB64,
		Endpoint:  app.cfg.Endpoint,
		Revoked:   false,
	}

	log.Printf("[%s] Initiating P2P Handshake with endpoint: %s", app.cfg.AgentName, req.TargetEndpoint)

	myInfoBytes, _ := json.Marshal(myInfo)
	resp, err := http.Post(req.TargetEndpoint+"/handshake", "application/json", bytes.NewBuffer(myInfoBytes))
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Handshake failed: %v", err)})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		w.WriteHeader(resp.StatusCode)
		w.Write(respBytes)
		return
	}

	var partnerInfo peers.PeerInfo
	if err := json.NewDecoder(resp.Body).Decode(&partnerInfo); err != nil {
		http.Error(w, "Failed to decode partner response", http.StatusInternalServerError)
		return
	}

	// Check if partner is blacklisted
	if app.blacklist.IsBlacklisted(partnerInfo.DID) {
		log.Printf("[%s] Rejecting handshake response from blacklisted partner %s", app.cfg.AgentName, partnerInfo.DID)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("cannot handshake with blacklisted peer: %s", partnerInfo.DID)})
		return
	}

	// Register partner locally
	if err := app.peersStore.AddPeer(partnerInfo); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to store partner peer: %v", err)})
		return
	}

	log.Printf("[%s] Handshake complete! Registered peer: %s", app.cfg.AgentName, partnerInfo.DID)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "handshake_success", "peer": partnerInfo.DID})
}

// handleSignMessage signs a message for the local cognitive agent.
func (app *KeyGuardApp) handleSignMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Validate payload against rules
	if err := rules.ValidatePayload(bodyBytes); err != nil {
		log.Printf("[%s] Rejecting sign request: %v", app.cfg.AgentName, err)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Wrap in DIDComm plaintext message
	didcommMsg := &didcomm.DIDCommMessage{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		Type:        "https://didcomm.org/basicmessage/2.0/message",
		Body:        make(map[string]interface{}),
		From:        app.cfg.DID,
		CreatedTime: time.Now().Unix(),
		ExpiresTime: time.Now().Add(5 * time.Minute).Unix(),
	}

	var parsedBody map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &parsedBody); err == nil {
		didcommMsg.Body = parsedBody
	} else {
		didcommMsg.Body = map[string]interface{}{"content": string(bodyBytes)}
	}

	// Sign message
	signed, err := didcomm.SignMessage(didcommMsg, app.privKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to sign message: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signed)
}

// handleSendMessage resolves, signs, and posts a message to a peer DID.
func (app *KeyGuardApp) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ToDID   string                 `json:"to_did"`
		Payload map[string]interface{} `json:"payload"`
		Type    string                 `json:"type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 1. Check local blacklist
	if app.blacklist.IsBlacklisted(req.ToDID) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Recipient %s is local blacklisted", req.ToDID)})
		return
	}

	// 2. Resolve locally
	peer, err := app.peersStore.ResolvePeer(req.ToDID)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to resolve DID locally: %v", err)})
		return
	}

	if peer.Revoked {
		app.blacklist.Add(req.ToDID, 10*time.Minute) // Cache revocation locally
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Recipient %s is revoked locally", req.ToDID)})
		return
	}

	// 3. Validate rules on the payload
	payBytes, _ := json.Marshal(req.Payload)
	if err := rules.ValidatePayload(payBytes); err != nil {
		log.Printf("[%s] Rejecting send request due to rule violation: %v", app.cfg.AgentName, err)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// 4. Wrap in DIDComm plain message
	msgType := req.Type
	if msgType == "" {
		msgType = "https://didcomm.org/basicmessage/2.0/message"
	}
	didcommMsg := &didcomm.DIDCommMessage{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		Type:        msgType,
		Body:        req.Payload,
		From:        app.cfg.DID,
		To:          []string{req.ToDID},
		CreatedTime: time.Now().Unix(),
		ExpiresTime: time.Now().Add(5 * time.Minute).Unix(),
	}

	// 5. Sign message
	signed, err := didcomm.SignMessage(didcommMsg, app.privKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to sign: %v", err), http.StatusInternalServerError)
		return
	}

	// 6. Transmit P2P
	signedBytes, _ := json.Marshal(signed)
	resp, err := http.Post(peer.Endpoint+"/receive-message", "application/json", bytes.NewBuffer(signedBytes))
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to deliver message to peer: %v", err)})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		w.WriteHeader(resp.StatusCode)
		w.Write(respBytes)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "delivered"})
}

// handleReceiveMessage handles incoming DIDComm messages from other peers.
func (app *KeyGuardApp) handleReceiveMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var signed didcomm.SignedMessage
	if err := json.NewDecoder(r.Body).Decode(&signed); err != nil {
		http.Error(w, "Invalid signed envelope", http.StatusBadRequest)
		return
	}

	// Unpack JWS to check sender DID
	if len(signed.Signatures) == 0 {
		http.Error(w, "Missing signatures", http.StatusBadRequest)
		return
	}

	// Decode payload to read 'from' field
	payloadBytes, err := base64.RawURLEncoding.DecodeString(signed.Payload)
	if err != nil {
		http.Error(w, "Failed to decode payload base64", http.StatusBadRequest)
		return
	}

	var rawMsg didcomm.DIDCommMessage
	if err := json.Unmarshal(payloadBytes, &rawMsg); err != nil {
		http.Error(w, "Invalid inner DIDComm message JSON", http.StatusBadRequest)
		return
	}

	senderDID := rawMsg.From
	if senderDID == "" {
		http.Error(w, "Missing sender DID ('from')", http.StatusBadRequest)
		return
	}

	// 1. Check local blacklist cache
	if app.blacklist.IsBlacklisted(senderDID) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Sender is blacklisted locally"})
		return
	}

	// 2. Resolve sender locally
	peer, err := app.peersStore.ResolvePeer(senderDID)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to resolve sender DID locally: %v", err)})
		return
	}

	if peer.Revoked {
		app.blacklist.Add(senderDID, 10*time.Minute) // cache it
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Sender DID is revoked locally"})
		return
	}

	// 3. Verify JWS signature using resolved Ed25519 public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
	if err != nil {
		http.Error(w, "Failed to decode resolved public key", http.StatusInternalServerError)
		return
	}

	msg, err := didcomm.VerifyMessage(&signed, ed25519.PublicKey(pubKeyBytes))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Signature verification failed: %v", err)})
		return
	}

	// 4. Handle auto-revocation types immediately
	if msg.Type == "https://didcomm.org/revocation/1.0/revoke" {
		log.Printf("[%s] RECEIVED REVOCATION ALERT FROM %s. Blacklisting peer immediately!", app.cfg.AgentName, senderDID)
		app.blacklist.Add(senderDID, 10*time.Minute)
		_ = app.peersStore.RevokePeer(senderDID)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "revoked_acknowledged"})
		return
	}

	// 5. Append to inbox for Python cognitive layer to read
	app.inboxMu.Lock()
	app.inbox = append(app.inbox, msg)
	app.inboxMu.Unlock()

	log.Printf("[%s] Received secure message from %s (ID: %s)", app.cfg.AgentName, msg.From, msg.ID)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

// handleBlacklist manually blacklists a peer.
func (app *KeyGuardApp) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			DID string `json:"did"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}

		log.Printf("[%s] Manually blacklisting DID %s for 10 minutes", app.cfg.AgentName, req.DID)
		app.blacklist.Add(req.DID, 10*time.Minute)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "blacklisted"})
	} else if r.Method == http.MethodDelete {
		var req struct {
			DID string `json:"did"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}

		log.Printf("[%s] Manually removing DID %s from blacklist", app.cfg.AgentName, req.DID)
		app.blacklist.Remove(req.DID)
		_ = app.peersStore.UnrevokePeer(req.DID)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "removed"})
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleInbox serves the received message queue to the local cognitive layer and clears it.
func (app *KeyGuardApp) handleInbox(w http.ResponseWriter, r *http.Request) {
	app.inboxMu.Lock()
	defer app.inboxMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(app.inbox)

	// Clear inbox after polling (typical simple queue behavior)
	app.inbox = make([]*didcomm.DIDCommMessage, 0)
}

// handleResolve resolves a DID locally via the peers store.
func (app *KeyGuardApp) handleResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	did := r.URL.Query().Get("did")
	if did == "" {
		http.Error(w, "Missing did parameter", http.StatusBadRequest)
		return
	}

	peer, err := app.peersStore.ResolvePeer(did)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"did":        peer.DID,
		"public_key": peer.PublicKey,
		"endpoint":   peer.Endpoint,
		"revoked":    peer.Revoked,
	})
}
