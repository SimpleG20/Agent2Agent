package main

import (
	"bytes"
	"crypto/ecdh"
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

	"a2a-secure-net/key-guard/a2a"
	"a2a-secure-net/key-guard/agentcard"
	"a2a-secure-net/key-guard/blacklist"
	"a2a-secure-net/key-guard/credential"
	"a2a-secure-net/key-guard/crypto"
	"a2a-secure-net/key-guard/didcomm"
	"a2a-secure-net/key-guard/peers"
	"a2a-secure-net/key-guard/rules"
)

type Config struct {
	Port       string
	AgentName  string
	DID        string // did:key:z... (new) or did:custom:<name> (legacy)
	DIDKey     string // Always did:key:z... for crypto operations
	Endpoint   string
	DataDir    string
	LegacyMode bool   // If true, still uses did:custom:<name> for backwards compat
	CAURL      string // Credential Authority base URL
	CAEnabled  bool   // Enable VC verification
}

type KeyGuardApp struct {
	cfg        Config
	privKey    ed25519.PrivateKey
	pubKey     ed25519.PublicKey
	x25519Key  *ecdh.PrivateKey // X25519 key for JWE decryption
	peersStore *peers.PeersStore
	blacklist  *blacklist.Blacklist
	taskStore  *a2a.TaskStore
	credStore  *credential.CredentialStore
	crlCache   *credential.CRLCache
	inbox      []*didcomm.DIDCommMessage
	inboxMu    sync.Mutex
}

func main() {
	port := flag.String("port", "8001", "Port to run Key Guard server on")
	agentName := flag.String("name", "alfa", "Name of the agent (alfa or beta)")
	endpoint := flag.String("endpoint", "http://localhost:8001", "P2P public endpoint for this key guard")
	dataDir := flag.String("datadir", "./data", "Directory to store keys, peers and blacklist cache")
	legacyMode := flag.Bool("legacy-mode", false, "Use did:custom: instead of did:key: for backwards compat")
	caURL := flag.String("ca-url", "http://localhost:9001", "Credential Authority base URL")
	caEnabled := flag.Bool("ca-enabled", true, "Enable agent credential verification")
	flag.Parse()

	cfg := Config{
		Port:       *port,
		AgentName:  *agentName,
		DID:        "did:custom:" + *agentName, // placeholder, updated after key generation
		DIDKey:     "",
		Endpoint:   *endpoint,
		DataDir:    *dataDir,
		LegacyMode: *legacyMode,
		CAURL:      *caURL,
		CAEnabled:  *caEnabled,
	}

	app, err := InitializeApp(cfg)
	if err != nil {
		log.Fatalf("Initialization failed: %v", err)
	}

	log.Printf("[%s] Initialized Key Guard for %s (DID: %s)", app.cfg.AgentName, app.cfg.AgentName, app.cfg.DID)
	log.Printf("[%s] DID Key: %s", app.cfg.AgentName, app.cfg.DIDKey)

	// Setup Server
	mux := http.NewServeMux()
	mux.HandleFunc("/sign-message", app.handleSignMessage)
	mux.HandleFunc("/send-message", app.handleSendMessage)
	mux.HandleFunc("/receive-message", app.handleReceiveMessage)
	mux.HandleFunc("/blacklist", app.handleBlacklist)
	mux.HandleFunc("/inbox", app.handleInbox)
	mux.HandleFunc("/resolve", app.handleResolve)
	mux.HandleFunc("/agent-info", app.handleAgentInfo)
	mux.HandleFunc("/.well-known/agent-card", app.handleAgentCard)

	// A2A Task Protocol Endpoints (JSON-RPC)
	mux.HandleFunc("/a2a/tasks/send", app.handleTaskSend)
	mux.HandleFunc("/a2a/tasks/get", app.handleTaskGet)
	mux.HandleFunc("/a2a/tasks/cancel", app.handleTaskCancel)
	mux.HandleFunc("/a2a/tasks/list", app.handleTaskList)
	mux.HandleFunc("/a2a/tasks/sendSubscribe", app.handleTaskSendSubscribe)

	// Credential Endpoints
	mux.HandleFunc("/credential", app.handleCredential)
	mux.HandleFunc("/credential/request-issue", app.handleCredentialRequestIssue)

	// P2P Handshake Endpoints
	mux.HandleFunc("/handshake", app.handleHandshake)
	mux.HandleFunc("/handshake-peer", app.handleHandshakePeer)
	mux.HandleFunc("/handshake-vc", app.handleHandshakeVC)

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

	// 2. Generate did:key: from public key
	didKey := crypto.GenerateDIDKey(pub)
	cfg.DIDKey = didKey

	// Set DID based on mode
	if cfg.LegacyMode {
		cfg.DID = "did:custom:" + cfg.AgentName
	} else {
		cfg.DID = didKey
	}

	// 3. Initialize local Peers Store
	peersFile := filepath.Join(cfg.DataDir, cfg.AgentName, "peers.json")
	peersStore, err := peers.NewPeersStore(peersFile)
	if err != nil {
		return nil, fmt.Errorf("failed to init peers store: %w", err)
	}

	// 4. Initialize Blacklist cache
	blFile := filepath.Join(cfg.DataDir, cfg.AgentName, "blacklist.json")
	bl, err := blacklist.NewBlacklist(blFile)
	if err != nil {
		return nil, fmt.Errorf("failed to init blacklist: %w", err)
	}

	// 5. Derive X25519 key pair from Ed25519 keys (for JWE encryption)
	x25519Key, err := crypto.Ed25519PrivateKeyToX25519(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to derive X25519 key: %w", err)
	}

	// 6. Initialize A2A Task Store
	taskStore := a2a.NewTaskStore()

	// 7. Initialize Credential Store
	credStore, err := credential.NewCredentialStore(filepath.Join(cfg.DataDir, cfg.AgentName, "credentials.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to init credential store: %w", err)
	}

	// 8. Initialize CRL Cache with 5-minute TTL
	crlCache := credential.NewCRLCache(cfg.CAURL, 5*time.Minute)

	// 9. If CA enabled, fetch CA info and always request a fresh VC
	if cfg.CAEnabled {
		caDID, caPubKey, err := credential.FetchCAInfo(cfg.CAURL)
		if err != nil {
			log.Printf("[%s] WARNING: CA not reachable at %s (degraded mode): %v", cfg.AgentName, cfg.CAURL, err)
		} else {
			credStore.SetCAInfo(caDID, caPubKey)
			log.Printf("[%s] CA discovered: %s", cfg.AgentName, caDID)

			// Always request fresh VC on startup (cached VCs may have been signed
			// by a different CA key after CA restart)
			vc, err := credential.RequestCredentialFromCA(cfg.CAURL, cfg.DID, cfg.DIDKey, cfg.AgentName)
			if err != nil {
				log.Printf("[%s] WARNING: Failed to request credential from CA (degraded mode): %v", cfg.AgentName, err)
			} else {
				credStore.SetOwnVC(vc)
				log.Printf("[%s] Credential obtained from CA: %s (expires: %s)", cfg.AgentName, vc.ID, vc.ExpirationDate)
			}
		}
	}

	return &KeyGuardApp{
		cfg:        cfg,
		privKey:    priv,
		pubKey:     pub,
		x25519Key:  x25519Key,
		peersStore: peersStore,
		blacklist:  bl,
		taskStore:  taskStore,
		credStore:  credStore,
		crlCache:   crlCache,
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

	// Verify peer's VC if CA is enabled
	if app.cfg.CAEnabled {
		if peerInfo.CredentialVC != nil && app.credStore.GetCAPublicKey() != nil {
			if err := app.verifyPeerCredential(peerInfo.CredentialVC); err != nil {
				log.Printf("[%s] Rejecting handshake: peer %s credential invalid: %v", app.cfg.AgentName, peerInfo.DID, err)
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Peer credential invalid: %v", err)})
				return
			}
		} else if !app.cfg.LegacyMode {
			log.Printf("[%s] Rejecting handshake: peer %s has no verifiable credential", app.cfg.AgentName, peerInfo.DID)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Peer has no verifiable credential"})
			return
		}
	}

	// Save peer
	if err := app.peersStore.AddPeer(peerInfo); err != nil {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Respond with own DID information to achieve mutual trust
	pubKeyB64 := base64.StdEncoding.EncodeToString(app.pubKey)
	x25519PubB64 := base64.StdEncoding.EncodeToString(app.x25519Key.PublicKey().Bytes())
	resp := peers.PeerInfo{
		DID:             app.cfg.DID,
		DIDKey:          app.cfg.DIDKey,
		PublicKey:       pubKeyB64,
		X25519PublicKey: x25519PubB64,
		Endpoint:        app.cfg.Endpoint,
		Revoked:         false,
	}

	// Include own VC in response if available
	if ownVC := app.credStore.GetOwnVC(); ownVC != nil {
		vcBytes, _ := json.Marshal(ownVC)
		resp.CredentialVC = vcBytes
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
	x25519PubB64 := base64.StdEncoding.EncodeToString(app.x25519Key.PublicKey().Bytes())
	myInfo := peers.PeerInfo{
		DID:             app.cfg.DID,
		DIDKey:          app.cfg.DIDKey,
		PublicKey:       pubKeyB64,
		X25519PublicKey: x25519PubB64,
		Endpoint:        app.cfg.Endpoint,
		Revoked:         false,
	}

	// Include VC in handshake if available
	if ownVC := app.credStore.GetOwnVC(); ownVC != nil {
		vcBytes, _ := json.Marshal(ownVC)
		myInfo.CredentialVC = vcBytes
	}

	log.Printf("[%s] Initiating P2P Handshake with endpoint: %s", app.cfg.AgentName, req.TargetEndpoint)

	myInfoBytes, _ := json.Marshal(myInfo)

	// Try VC handshake first if CA is enabled
	handshakeEndpoint := "/handshake"
	if app.cfg.CAEnabled && app.credStore.GetOwnVC() != nil {
		handshakeEndpoint = "/handshake-vc"
	}

	resp, err := http.Post(req.TargetEndpoint+handshakeEndpoint, "application/json", bytes.NewBuffer(myInfoBytes))
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

	// Verify partner's VC if CA is enabled
	if app.cfg.CAEnabled {
		if partnerInfo.CredentialVC != nil && app.credStore.GetCAPublicKey() != nil {
			if err := app.verifyPeerCredential(partnerInfo.CredentialVC); err != nil {
				log.Printf("[%s] Rejecting handshake: partner %s credential invalid: %v", app.cfg.AgentName, partnerInfo.DID, err)
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Partner credential invalid: %v", err)})
				return
			}
		} else if !app.cfg.LegacyMode {
			log.Printf("[%s] Rejecting handshake: partner %s has no verifiable credential", app.cfg.AgentName, partnerInfo.DID)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Partner has no verifiable credential"})
			return
		}
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

	// 3. Verify recipient's VC if CA is enabled and peer provided one
	if app.cfg.CAEnabled && peer.CredentialVC != nil && app.credStore.GetCAPublicKey() != nil {
		if err := app.verifyPeerCredential(peer.CredentialVC); err != nil {
			log.Printf("[%s] Rejecting send: peer %s credential invalid: %v", app.cfg.AgentName, req.ToDID, err)
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Peer credential invalid: %v", err)})
			return
		}
	} else if app.cfg.CAEnabled && !app.cfg.LegacyMode && peer.CredentialVC == nil {
		// In non-legacy mode, require a VC
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Peer has no verifiable credential"})
		return
	}

	// 4. Validate rules on the payload
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

	// 5. Sign message (JWS)
	signed, err := didcomm.SignMessage(didcommMsg, app.privKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to sign: %v", err), http.StatusInternalServerError)
		return
	}

	// 6. Encrypt with JWE if peer supports X25519 encryption
	transportBytes, _ := json.Marshal(signed)
	if peer.X25519PublicKey != "" {
		xPubBytes, err := base64.StdEncoding.DecodeString(peer.X25519PublicKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to decode peer X25519 key: %v", err)})
			return
		}
		xPubKey, err := ecdh.X25519().NewPublicKey(xPubBytes)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to parse peer X25519 key: %v", err)})
			return
		}
		kid := peer.DIDKey
		if kid == "" {
			kid = peer.DID
		}
		jweBytes, err := didcomm.EncryptMessage(transportBytes, xPubKey, kid)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("JWE encryption failed: %v", err)})
			return
		}
		transportBytes = jweBytes
	}

	// 7. Transmit P2P
	resp, err := http.Post(peer.Endpoint+"/receive-message", "application/json", bytes.NewBuffer(transportBytes))
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

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Detect if this is a JWE (encrypted) or JWS (signed) message
	var signed didcomm.SignedMessage
	var jweCheck struct {
		Protected  string `json:"protected"`
		Ciphertext string `json:"ciphertext"`
		Tag        string `json:"tag"`
	}

	if json.Unmarshal(bodyBytes, &jweCheck) == nil && jweCheck.Protected != "" && jweCheck.Ciphertext != "" {
		// This is a JWE — decrypt first
		plaintext, err := didcomm.DecryptMessage(bodyBytes, app.x25519Key)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("JWE decryption failed: %v", err)})
			return
		}
		if err := json.Unmarshal(plaintext, &signed); err != nil {
			http.Error(w, "Failed to parse decrypted JWS", http.StatusBadRequest)
			return
		}
	} else {
		// Legacy JWS (unencrypted)
		if err := json.Unmarshal(bodyBytes, &signed); err != nil {
			http.Error(w, "Invalid signed envelope", http.StatusBadRequest)
			return
		}
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

	// 3. Verify sender's VC if CA is enabled and credential is present
	if app.cfg.CAEnabled && peer.CredentialVC != nil && app.credStore.GetCAPublicKey() != nil {
		if err := app.verifyPeerCredential(peer.CredentialVC); err != nil {
			log.Printf("[%s] Rejecting message: sender %s credential invalid: %v", app.cfg.AgentName, senderDID, err)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Sender credential invalid: %v", err)})
			return
		}
	} else if app.cfg.CAEnabled && !app.cfg.LegacyMode && peer.CredentialVC == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Sender has no verifiable credential"})
		return
	}

	// 4. Verify JWS signature using resolved Ed25519 public key
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
		"did":               peer.DID,
		"public_key":        peer.PublicKey,
		"x25519_public_key": peer.X25519PublicKey,
		"endpoint":          peer.Endpoint,
		"revoked":           peer.Revoked,
	})
}

// --- A2A Task Protocol Handlers ---

// handleTaskSend creates a new task via JSON-RPC 2.0.
// POST /a2a/tasks/send
func (app *KeyGuardApp) handleTaskSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req a2a.JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(a2a.NewJSONRPCError(req.ID, -32700, "Parse error: invalid JSON"))
		return
	}

	// Parse params
	paramsBytes, _ := json.Marshal(req.Params)
	var taskParams a2a.TaskSendParams
	if err := json.Unmarshal(paramsBytes, &taskParams); err != nil {
		json.NewEncoder(w).Encode(a2a.NewJSONRPCError(req.ID, -32602, "Invalid params"))
		return
	}

	if taskParams.ID == "" {
		json.NewEncoder(w).Encode(a2a.NewJSONRPCError(req.ID, -32602, "Missing task ID"))
		return
	}

	// Create task in submitted state
	task := &a2a.Task{
		ID:        taskParams.ID,
		SessionID: taskParams.SessionID,
		Status: a2a.TaskStatus{
			State:   a2a.TaskStateSubmitted,
			Message: &taskParams.Message,
		},
		Metadata: taskParams.Metadata,
	}

	if err := app.taskStore.Create(task); err != nil {
		json.NewEncoder(w).Encode(a2a.NewJSONRPCError(req.ID, -32603, err.Error()))
		return
	}

	// Transition to working (simple auto-accept)
	_ = task.Transition(a2a.TaskStateWorking)

	log.Printf("[%s] Task created: %s (session: %s)", app.cfg.AgentName, task.ID, task.SessionID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a2a.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"id":     task.ID,
			"status": task.Status,
		},
	})
}

// handleTaskGet retrieves the current status of a task.
// POST /a2a/tasks/get
func (app *KeyGuardApp) handleTaskGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req a2a.JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(a2a.NewJSONRPCError(req.ID, -32700, "Parse error"))
		return
	}

	paramsBytes, _ := json.Marshal(req.Params)
	var taskParams a2a.TaskGetParams
	if err := json.Unmarshal(paramsBytes, &taskParams); err != nil || taskParams.ID == "" {
		json.NewEncoder(w).Encode(a2a.NewJSONRPCError(req.ID, -32602, "Missing task ID"))
		return
	}

	task, err := app.taskStore.Get(taskParams.ID)
	if err != nil {
		json.NewEncoder(w).Encode(a2a.NewJSONRPCError(req.ID, -32000, err.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a2a.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"id":     task.ID,
			"status": task.Status,
		},
	})
}

// handleTaskCancel cancels a running task.
// POST /a2a/tasks/cancel
func (app *KeyGuardApp) handleTaskCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req a2a.JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(a2a.NewJSONRPCError(req.ID, -32700, "Parse error"))
		return
	}

	paramsBytes, _ := json.Marshal(req.Params)
	var taskParams a2a.TaskCancelParams
	if err := json.Unmarshal(paramsBytes, &taskParams); err != nil || taskParams.ID == "" {
		json.NewEncoder(w).Encode(a2a.NewJSONRPCError(req.ID, -32602, "Missing task ID"))
		return
	}

	err := app.taskStore.Update(taskParams.ID, func(t *a2a.Task) error {
		return t.Transition(a2a.TaskStateCanceled)
	})
	if err != nil {
		json.NewEncoder(w).Encode(a2a.NewJSONRPCError(req.ID, -32000, err.Error()))
		return
	}

	task, _ := app.taskStore.Get(taskParams.ID)
	log.Printf("[%s] Task canceled: %s", app.cfg.AgentName, taskParams.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a2a.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"id":     task.ID,
			"status": task.Status,
		},
	})
}

// handleTaskList returns all tasks in the store (for dashboard Task Explorer).
// GET /a2a/tasks/list
func (app *KeyGuardApp) handleTaskList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tasks := app.taskStore.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tasks": tasks,
	})
}

// handleTaskSendSubscribe creates a task and streams status updates via SSE.
// POST /a2a/tasks/sendSubscribe
// Returns Content-Type: text/event-stream with task_update events.
// Connection closes on terminal state, client disconnect, or 30s timeout.
func (app *KeyGuardApp) handleTaskSendSubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	var req a2a.JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(a2a.NewJSONRPCError(req.ID, -32700, "Parse error"))
		return
	}

	paramsBytes, _ := json.Marshal(req.Params)
	var taskParams a2a.TaskSendParams
	if err := json.Unmarshal(paramsBytes, &taskParams); err != nil {
		json.NewEncoder(w).Encode(a2a.NewJSONRPCError(req.ID, -32602, "Invalid params"))
		return
	}

	if taskParams.ID == "" {
		json.NewEncoder(w).Encode(a2a.NewJSONRPCError(req.ID, -32602, "Missing task ID"))
		return
	}

	// Create task in submitted state
	task := &a2a.Task{
		ID:        taskParams.ID,
		SessionID: taskParams.SessionID,
		Status: a2a.TaskStatus{
			State:   a2a.TaskStateSubmitted,
			Message: &taskParams.Message,
		},
		Metadata: taskParams.Metadata,
	}

	if err := app.taskStore.Create(task); err != nil {
		json.NewEncoder(w).Encode(a2a.NewJSONRPCError(req.ID, -32603, err.Error()))
		return
	}

	// Transition to working (simple auto-accept)
	_ = task.Transition(a2a.TaskStateWorking)

	log.Printf("[%s] Task created with SSE: %s (session: %s)", app.cfg.AgentName, task.ID, task.SessionID)

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Subscribe to task updates
	updateCh := app.taskStore.Subscribe(task.ID)
	defer app.taskStore.Unsubscribe(task.ID, updateCh)

	// Send initial task state event
	initialData, _ := json.Marshal(map[string]interface{}{
		"id":     task.ID,
		"status": task.Status,
	})
	fmt.Fprintf(w, "event: task_update\ndata: %s\n\n", initialData)
	flusher.Flush()

	// Stream updates until terminal state, client disconnect, or 30s timeout
	timeout := time.After(30 * time.Second)
	for {
		select {
		case update := <-updateCh:
			data, _ := json.Marshal(map[string]interface{}{
				"id":     update.ID,
				"status": update.Status,
			})
			fmt.Fprintf(w, "event: task_update\ndata: %s\n\n", data)
			flusher.Flush()

			// Terminate stream on final states
			if update.Status.State == a2a.TaskStateCompleted ||
				update.Status.State == a2a.TaskStateFailed ||
				update.Status.State == a2a.TaskStateCanceled {
				log.Printf("[%s] SSE stream ended for task %s (state: %s)", app.cfg.AgentName, task.ID, update.Status.State)
				return
			}
		case <-r.Context().Done():
			log.Printf("[%s] SSE client disconnected for task %s", app.cfg.AgentName, task.ID)
			return
		case <-timeout:
			fmt.Fprintf(w, "event: error\ndata: {\"error\":\"timeout\"}\n\n")
			flusher.Flush()
			return
		}
	}
}

// handleAgentCard serves the A2A Agent Card for capability discovery.
// GET /.well-known/agent-card
func (app *KeyGuardApp) handleAgentCard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	card := agentcard.NewAgentCard(
		app.cfg.AgentName,
		app.cfg.DID,
		"",
		app.cfg.Endpoint,
		agentcard.DefaultSkills(),
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(card)
}

// handleAgentInfo returns information about this agent (for cognitive layer discovery).
func (app *KeyGuardApp) handleAgentInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	pubKeyB64 := base64.StdEncoding.EncodeToString(app.pubKey)
	x25519PubB64 := base64.StdEncoding.EncodeToString(app.x25519Key.PublicKey().Bytes())

	info := map[string]interface{}{
		"name":              app.cfg.AgentName,
		"did":               app.cfg.DID,
		"did_key":           app.cfg.DIDKey,
		"public_key":        pubKeyB64,
		"x25519_public_key": x25519PubB64,
		"endpoint":          app.cfg.Endpoint,
		"legacy_mode":       app.cfg.LegacyMode,
		"ca_enabled":        app.cfg.CAEnabled,
		"ca_url":            app.cfg.CAURL,
	}

	if ownVC := app.credStore.GetOwnVC(); ownVC != nil {
		info["credential_id"] = ownVC.ID
		info["credential_expires"] = ownVC.ExpirationDate
	}

	json.NewEncoder(w).Encode(info)
}

// --- Credential Endpoints ---

// handleCredential returns the agent's own VC and CA status.
// GET /credential
func (app *KeyGuardApp) handleCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	vc := app.credStore.GetOwnVC()
	if vc == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "no_credential",
			"ca_enabled": app.cfg.CAEnabled,
			"ca_did":     app.credStore.GetCADID(),
		})
		return
	}

	caDID := app.credStore.GetCADID()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "available",
		"credential": vc,
		"ca_did":     caDID,
		"ca_enabled": app.cfg.CAEnabled,
	})
}

// handleCredentialRequestIssue requests a new VC from the CA.
// POST /credential/request-issue
func (app *KeyGuardApp) handleCredentialRequestIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !app.cfg.CAEnabled {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "CA integration is disabled"})
		return
	}

	// Ensure we have CA info
	if app.credStore.GetCADID() == "" {
		caDID, caPub, err := credential.FetchCAInfo(app.cfg.CAURL)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("CA not reachable: %v", err)})
			return
		}
		app.credStore.SetCAInfo(caDID, caPub)
	}

	vc, err := credential.RequestCredentialFromCA(app.cfg.CAURL, app.cfg.DID, app.cfg.DIDKey, app.cfg.AgentName)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("VC request failed: %v", err)})
		return
	}

	app.credStore.SetOwnVC(vc)
	log.Printf("[%s] Credential re-issued: %s (expires: %s)", app.cfg.AgentName, vc.ID, vc.ExpirationDate)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "issued",
		"credential": vc,
	})
}

// --- VC-Enhanced Handshake ---

// handleHandshakeVC is a VC-enhanced handshake endpoint.
// POST /handshake-vc
// Same as /handshake but verifies the peer's credential before accepting.
func (app *KeyGuardApp) handleHandshakeVC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var peerInfo peers.PeerInfo
	if err := json.NewDecoder(r.Body).Decode(&peerInfo); err != nil {
		http.Error(w, "Invalid handshake payload", http.StatusBadRequest)
		return
	}

	log.Printf("[%s] Received VC handshake request from %s at %s", app.cfg.AgentName, peerInfo.DID, peerInfo.Endpoint)

	// Check blacklist
	if app.blacklist.IsBlacklisted(peerInfo.DID) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "peer is blacklisted"})
		return
	}

	// Verify peer's VC if present and CA is enabled
	if peerInfo.CredentialVC != nil && app.cfg.CAEnabled {
		if err := app.verifyPeerCredential(peerInfo.CredentialVC); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("credential verification failed: %v", err)})
			return
		}
	} else if app.cfg.CAEnabled && !app.cfg.LegacyMode {
		// In non-legacy mode, VCs are required
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "credential required from peer but not provided"})
		return
	}

	// Save peer
	if err := app.peersStore.AddPeer(peerInfo); err != nil {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Respond with own DID + VC
	pubKeyB64 := base64.StdEncoding.EncodeToString(app.pubKey)
	x25519PubB64 := base64.StdEncoding.EncodeToString(app.x25519Key.PublicKey().Bytes())
	resp := peers.PeerInfo{
		DID:             app.cfg.DID,
		DIDKey:          app.cfg.DIDKey,
		PublicKey:       pubKeyB64,
		X25519PublicKey: x25519PubB64,
		Endpoint:        app.cfg.Endpoint,
		Revoked:         false,
	}

	// Include own VC in response
	if ownVC := app.credStore.GetOwnVC(); ownVC != nil {
		vcBytes, _ := json.Marshal(ownVC)
		resp.CredentialVC = vcBytes
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// verifyPeerCredential unmarshals and locally verifies a peer's raw VC.
func (app *KeyGuardApp) verifyPeerCredential(vcRaw json.RawMessage) error {
	var vc credential.VerifiableCredential
	if err := json.Unmarshal(vcRaw, &vc); err != nil {
		return fmt.Errorf("invalid credential format: %w", err)
	}

	caPub := app.credStore.GetCAPublicKey()
	if caPub == nil {
		return fmt.Errorf("CA public key not available")
	}

	return credential.VerifyCredentialLocally(&vc, caPub, app.crlCache)
}
