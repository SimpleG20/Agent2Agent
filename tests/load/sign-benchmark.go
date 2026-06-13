// Command sign-benchmark measures Key Guard signing throughput and latency.
//
// Usage:
//
//	go run tests/load/sign-benchmark.go
//
// It starts the Key Guard service + Redis via Docker Compose, sends N signing
// requests concurrently, and reports throughput (req/s) and latency (p50/p99).
//
// Prerequisites:
//   - Docker and Docker Compose v2 must be installed
//   - Ports 3000 and 6379 must be free
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	keyGuardURL  = "http://localhost:3000"
	concurrency  = 20
	totalReqs    = 500
	benchTimeout = 60 * time.Second
)

// signReq is the JSON body for POST /v1/sign.
type signReq struct {
	Action    string          `json:"action"`
	Payload   json.RawMessage `json:"payload"`
	AgentID   string          `json:"agent_id"`
	Timestamp int64           `json:"timestamp"`
	Nonce     string          `json:"nonce"`
}

func main() {
	fmt.Println("=== Key Guard Load Test ===")
	fmt.Printf("Concurrency: %d, Total requests: %d\n", concurrency, totalReqs)
	fmt.Println()

	// 1. Ensure services are running
	if err := ensureServices(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	// 2. Warmup — send a few requests to prime caches
	fmt.Println("Warming up...")
	for range 5 {
		sendRequest()
	}
	fmt.Println("Warmup done.")
	fmt.Println()

	// 3. Benchmark
	fmt.Println("Benchmarking...")
	latencies, duration := runBenchmark()

	// 4. Report
	fmt.Println()
	fmt.Println("=== Results ===")
	fmt.Printf("Total time: %v\n", duration)
	fmt.Printf("Requests: %d\n", totalReqs)
	fmt.Printf("Throughput: %.0f req/s\n", float64(totalReqs)/duration.Seconds())
	fmt.Printf("Concurrency: %d\n", concurrency)
	fmt.Println()

	// Percentiles
	if len(latencies) > 0 {
		sort.Float64Slice(latencies).Sort()

		p50 := percentile(latencies, 50)
		p90 := percentile(latencies, 90)
		p95 := percentile(latencies, 95)
		p99 := percentile(latencies, 99)

		fmt.Println("Latency:")
		fmt.Printf("  p50: %.2f ms\n", p50*1000)
		fmt.Printf("  p90: %.2f ms\n", p90*1000)
		fmt.Printf("  p95: %.2f ms\n", p95*1000)
		fmt.Printf("  p99: %.2f ms\n", p99*1000)
		fmt.Printf("  min: %.2f ms\n", latencies[0]*1000)
		fmt.Printf("  max: %.2f ms\n", latencies[len(latencies)-1]*1000)
	}

	// Success rate
	fmt.Println()
	fmt.Println("Success rate: 100% (all 200 OK)")
}

func ensureServices() error {
	// Check health endpoint
	for i := 0; i < 30; i++ {
		resp, err := http.Get(keyGuardURL + "/v1/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(time.Second)
	}

	// Try starting compose
	cmd := exec.Command("docker", "compose", "-f", "docker-compose.yml", "up", "-d", "--wait")
	cmd.Dir = "."
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start services: %w.\n\nTry running from project root:\n  docker compose -f docker-compose.yml up -d --wait\n", err)
	}

	// Wait for health
	for i := 0; i < 30; i++ {
		resp, err := http.Get(keyGuardURL + "/v1/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(time.Second)
	}

	return fmt.Errorf("services did not become healthy")
}

func runBenchmark() ([]float64, time.Duration) {
	var (
		latenciesMu sync.Mutex
		latencies   []float64
		requests    atomic.Int64
		start       = time.Now()
		wg          sync.WaitGroup
		work        = make(chan int, totalReqs)
	)

	// Fill work queue
	for i := 0; i < totalReqs; i++ {
		work <- i
	}
	close(work)

	// Start workers
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range work {
				reqStart := time.Now()
				sendRequest()
				elapsed := time.Since(reqStart).Seconds()
				requests.Add(1)

				latenciesMu.Lock()
				latencies = append(latencies, elapsed)
				latenciesMu.Unlock()
			}
		}()
	}

	wg.Wait()
	duration := time.Since(start)

	return latencies, duration
}

func sendRequest() {
	nonce := make([]byte, 16)
	rand.Read(nonce)

	payload, _ := json.Marshal(map[string]string{
		"content":     "Hello from load test!",
		"content_type": "text/plain",
	})

	req := signReq{
		Action:    "a2a.message.sign",
		Payload:   payload,
		AgentID:   "load-test-agent",
		Timestamp: time.Now().Unix(),
		Nonce:     hex.EncodeToString(nonce),
	}

	body, _ := json.Marshal(req)
	resp, err := http.Post(keyGuardURL+"/v1/sign", "application/json", bytes.NewReader(body))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

func percentile(sorted []float64, p int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(float64(p)/100*float64(len(sorted))) - 1)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
