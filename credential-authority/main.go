package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"a2a-secure-net/credential-authority/credential"
	"a2a-secure-net/credential-authority/registry"
)

func main() {
	port := 9001
	datadir := "./data_ca"
	name := "A2A Credential Authority"

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-port":
			if i+1 < len(args) {
				if p, err := strconv.Atoi(args[i+1]); err == nil {
					port = p
				}
				i++
			}
		case "-datadir":
			if i+1 < len(args) {
				datadir = args[i+1]
				i++
			}
		case "-name":
			if i+1 < len(args) {
				name = args[i+1]
				i++
			}
		}
	}

	if v := os.Getenv("CA_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			port = p
		}
	}
	if v := os.Getenv("CA_DATADIR"); v != "" {
		datadir = v
	}
	if v := os.Getenv("CA_NAME"); v != "" {
		name = v
	}

	ca, err := NewCredentialAuthority(name, datadir)
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	log.Printf("✅ Credential Authority started")
	log.Printf("   Name: %s", ca.Name())
	log.Printf("   DID: %s", ca.DID())
	log.Printf("   Port: %d", port)
	log.Printf("   DataDir: %s", datadir)
	log.Printf("   Total Issued: %d", ca.TotalIssued())
	log.Printf("   Total Revoked: %d", ca.TotalRevoked())

	mux := http.NewServeMux()
	mux.HandleFunc("/ca/info", handleCAInfo(ca))
	mux.HandleFunc("/credential/issue", handleIssue(ca))
	mux.HandleFunc("/credential/verify", handleVerify(ca))
	mux.HandleFunc("/credential/revoke", handleRevoke(ca))
	mux.HandleFunc("/credential/crl", handleCRL(ca))
	mux.HandleFunc("/credential/list", handleListCredentials(ca))
	mux.HandleFunc("/credential/status/", handleStatus(ca))

	addr := fmt.Sprintf(":%d", port)
	log.Printf("HTTP server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// handleCAInfo returns CA metadata (name, DID, public key, statistics).
func handleCAInfo(ca *CredentialAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"name":            ca.Name(),
			"did":             ca.DID(),
			"publicKeyBase64": base64.StdEncoding.EncodeToString(ca.PublicKey()),
			"totalIssued":     ca.TotalIssued(),
			"totalRevoked":    ca.TotalRevoked(),
		})
	}
}

// handleIssue processes credential issuance requests.
func handleIssue(ca *CredentialAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			DID                string `json:"did"`
			PublicKeyMultibase string `json:"publicKeyMultibase"`
			AgentName          string `json:"agentName"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
			return
		}

		vc, err := ca.IssueCredential(req.DID, req.PublicKeyMultibase, req.AgentName)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, vc)
	}
}

// handleVerify checks a credential's validity.
func handleVerify(ca *CredentialAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Credential json.RawMessage `json:"credential"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
			return
		}

		var vc credential.VerifiableCredential
		if err := json.Unmarshal(req.Credential, &vc); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid credential JSON: " + err.Error()})
			return
		}

		if err := ca.VerifyCredential(&vc); err != nil {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"verified": false,
				"error":    err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"verified": true,
			"subject":  vc.CredentialSubject.ID,
			"issuer":   vc.Issuer,
			"expires":  vc.ExpirationDate,
		})
	}
}

// handleRevoke revokes a credential by ID.
func handleRevoke(ca *CredentialAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			CredentialID string `json:"credentialId"`
			Reason       string `json:"reason,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
			return
		}

		if err := ca.RevokeCredential(req.CredentialID, req.Reason); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"revoked": true,
			"id":      req.CredentialID,
		})
	}
}

// handleCRL returns the Certificate Revocation List.
func handleCRL(ca *CredentialAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		crl := ca.GetCRL()
		if crl == nil {
			crl = []registry.RevokedEntry{}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"totalRevoked": len(crl),
			"entries":      crl,
		})
	}
}

// handleStatus returns the status of a specific credential.
func handleStatus(ca *CredentialAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		parts := strings.SplitN(r.URL.Path, "/credential/status/", 2)
		if len(parts) != 2 || parts[1] == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing credential ID"})
			return
		}
		vcID := parts[1]

		status, err := ca.GetCredentialStatus(vcID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, status)
	}
}

// handleListCredentials returns summary info for all issued credentials.
func handleListCredentials(ca *CredentialAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		issued := ca.ListIssued()
		if issued == nil {
			issued = []registry.IssuedCredentialInfo{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"totalIssued": len(issued),
			"credentials": issued,
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
