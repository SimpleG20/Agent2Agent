// Command key-guard is the HTTP server entrypoint for the Key Guard service.
//
// It wires together the crypto layer, validation engine, Redis-backed storage,
// and Prometheus metrics into a single HTTP service that agents call to sign
// A2A intents.
//
// Environment variables:
//   - KEY_GUARD_PORT:      HTTP listen port (default: "3000")
//   - KEY_GUARD_SEED:      hex-encoded Ed25519 seed (64 hex chars, required)
//   - REDIS_URL:           Redis connection URL (default: "redis://localhost:6379")
//   - REDIS_TIMEOUT_MS:    Redis operation timeout in milliseconds (default: 100)
package main

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/stumgart/a2a/key-guard/internal/crypto"
	"github.com/stumgart/a2a/key-guard/internal/server"
	"github.com/stumgart/a2a/key-guard/internal/storage"
	"github.com/stumgart/a2a/key-guard/internal/validation"
)

func main() {
	// --- Configuration from environment ---
	port := getEnv("KEY_GUARD_PORT", "3000")
	redisURL := getEnv("REDIS_URL", "redis://localhost:6379")
	seedHex := os.Getenv("KEY_GUARD_SEED")
	redisTimeoutMs := getEnvInt("REDIS_TIMEOUT_MS", 100)

	if seedHex == "" {
		log.Fatal("KEY_GUARD_SEED is required — set a 64-char hex-encoded Ed25519 seed")
	}

	// --- Load or generate key ---
	seed, err := crypto.SeedFromHex(seedHex)
	if err != nil {
		log.Fatalf("invalid KEY_GUARD_SEED: %v", err)
	}

	privKey, err := crypto.KeyFromSeed(seed)
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}

	pubKey := privKey.Public().(ed25519.PublicKey)
	serviceDID, err := crypto.DIDFromPublicKey(pubKey)
	if err != nil {
		log.Fatalf("failed to derive service DID: %v", err)
	}

	log.Printf("service DID: %s", serviceDID)
	log.Printf("public key (hex): %x", pubKey)

	// --- Connect to Redis ---
	redisClient, err := storage.NewRedisClient(redisURL, time.Duration(redisTimeoutMs)*time.Millisecond)
	if err != nil {
		log.Fatalf("failed to connect to Redis: %v", err)
	}
	defer redisClient.Close()

	// --- Storage layer ---
	revocationStore := storage.NewRevocationStore(redisClient)
	nonceStore := storage.NewNonceStore(0) // uses default 5min TTL
	nonceStore.Start()
	defer nonceStore.Stop()

	// --- Budget / rate limiting ---
	budgetStore := validation.NewBudgetStore()

	// --- HTTP server ---
	srv, err := server.NewKeyGuardServer(privKey, revocationStore, nonceStore, budgetStore)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}

	addr := fmt.Sprintf(":%s", port)
	log.Printf("starting Key Guard on %s", addr)

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      srv.Handler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if val := os.Getenv(key); val != "" {
		n, err := strconv.Atoi(val)
		if err == nil {
			return n
		}
		log.Printf("warning: invalid %s=%q, using default %d", key, val, fallback)
	}
	return fallback
}
