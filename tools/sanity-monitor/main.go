// Sanity Monitor — deterministic anomaly detector for LLM agent logs.
//
// Watches an agent log file, runs pattern-matching rules for hallucination
// and prompt injection, and publishes revocation events to Redis when
// score thresholds are reached.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/stumgart/a2a/sanity-monitor/rules"
)

// Config holds all configuration from environment variables.
type Config struct {
	LogPath                string
	RedisURL               string
	PollInterval           time.Duration
	RevocationTTL          time.Duration
	ScoreWindow            time.Duration
	HallucinationThreshold int
	InjectionThreshold     int
}

// LogEntry represents a parsed structured log line.
type LogEntry struct {
	DID     string `json:"did"`
	AgentID string `json:"agent_id"`
	Message string `json:"message"`
	Content string `json:"content"`
	Text    string `json:"text"`
}

func loadConfig() Config {
	cfg := Config{
		LogPath:                envOrDefault("AGENT_LOG_PATH", "/var/log/agent/agent.log"),
		RedisURL:               envOrDefault("REDIS_URL", "redis://redis:6379"),
		PollInterval:           durationEnvOrDefault("POLL_INTERVAL_MS", 500),
		RevocationTTL:          durationEnvOrDefault("REVOCATION_TTL_SEC", 300),
		ScoreWindow:            durationEnvOrDefault("SCORE_WINDOW_SEC", 60),
		HallucinationThreshold: intEnvOrDefault("HALLUCINATION_THRESHOLD", 5),
		InjectionThreshold:     intEnvOrDefault("INJECTION_THRESHOLD", 5),
	}
	return cfg
}

func main() {
	cfg := loadConfig()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("[BOOT] starting sanity-monitor (id=%s)", uuid.New().String()[:8])
	log.Printf("[BOOT] config: log_path=%s poll=%s window=%s ttl=%s",
		cfg.LogPath, cfg.PollInterval, cfg.ScoreWindow, cfg.RevocationTTL)

	// Connect to Redis.
	opts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Fatalf("[FATAL] invalid REDIS_URL %q: %v", redactedURL(cfg.RedisURL), err)
	}
	rdb := redis.NewClient(opts)
	defer rdb.Close()

	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("[FATAL] redis unreachable: %v", err)
	}
	log.Println("[BOOT] redis connected")

	// Build rules pipeline.
	publisher := rules.NewRevocationPublisher(&redisAdapter{rdb: rdb}, cfg.RevocationTTL)
	hallucinationRule := rules.NewHallucinationRule()
	injectionRule := rules.NewInjectionRule()

	hallucinationTracker := rules.NewScoreTracker(cfg.HallucinationThreshold, cfg.ScoreWindow)
	injectionTracker := rules.NewScoreTracker(cfg.InjectionThreshold, cfg.ScoreWindow)

	// Start file watcher loop.
	watcher := &fileWatcher{
		path:     cfg.LogPath,
		interval: cfg.PollInterval,
	}

	log.Printf("[BOOT] watching %s (poll=%s)", cfg.LogPath, cfg.PollInterval)

	sessionID := uuid.New().String()[:8]

	watcher.Start(ctx, func(line string) {
		processLine(ctx, line, sessionID,
			hallucinationRule, injectionRule,
			hallucinationTracker, injectionTracker,
			publisher)
	})
}

func processLine(
	ctx context.Context,
	line string,
	sessionID string,
	hallucinationRule *rules.HallucinationRule,
	injectionRule *rules.InjectionRule,
	hallucinationTracker *rules.ScoreTracker,
	injectionTracker *rules.ScoreTracker,
	publisher *rules.RevocationPublisher,
) {
	if strings.TrimSpace(line) == "" {
		return
	}

	// Try to parse as JSONL for structured fields.
	agentDID, content := parseLogLine(line)

	now := time.Now()

	// Run hallucination rule.
	if result := hallucinationRule.Evaluate(content, agentDID); result != nil {
		log.Printf("[MATCH] session=%s rule=%s did=%s score=%d pattern=%q",
			sessionID, result.RuleName, agentDID, result.Score, result.Pattern)

		if agentDID != "" && hallucinationTracker.Add(agentDID, result.Score, now) {
			log.Printf("[ALERT] session=%s rule=%s did=%s total_score=%d threshold=%d — REVOKING",
				sessionID, result.RuleName, agentDID,
				hallucinationTracker.Score(agentDID, now),
				hallucinationTracker.Threshold())
			if err := publisher.Publish(ctx, *result); err != nil {
				log.Printf("[ERROR] publish failed: %v", err)
			}
			hallucinationTracker.Reset(agentDID)
		}
	}

	// Run injection rule.
	if result := injectionRule.Evaluate(content, agentDID); result != nil {
		log.Printf("[MATCH] session=%s rule=%s did=%s score=%d pattern=%q",
			sessionID, result.RuleName, agentDID, result.Score, result.Pattern)

		if agentDID != "" && injectionTracker.Add(agentDID, result.Score, now) {
			log.Printf("[ALERT] session=%s rule=%s did=%s total_score=%d threshold=%d — REVOKING",
				sessionID, result.RuleName, agentDID,
				injectionTracker.Score(agentDID, now),
				injectionTracker.Threshold())
			if err := publisher.Publish(ctx, *result); err != nil {
				log.Printf("[ERROR] publish failed: %v", err)
			}
			injectionTracker.Reset(agentDID)
		}
	}
}

// parseLogLine extracts agent DID and message content from a log line.
// Supports JSONL and plain text.
func parseLogLine(line string) (agentDID, content string) {
	var entry LogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		// Plain text — use the whole line as content, no DID.
		return "", line
	}

	// Extract DID from available fields.
	switch {
	case entry.DID != "":
		agentDID = entry.DID
	case entry.AgentID != "":
		agentDID = entry.AgentID
	}

	// Extract content from available fields.
	switch {
	case entry.Message != "":
		content = entry.Message
	case entry.Content != "":
		content = entry.Content
	case entry.Text != "":
		content = entry.Text
	default:
		content = line
	}

	return agentDID, content
}

// fileWatcher tails a file by polling for new content.
type fileWatcher struct {
	path     string
	interval time.Duration
}

// Start begins polling the file. It blocks until ctx is cancelled.
func (fw *fileWatcher) Start(ctx context.Context, handler func(string)) {
	// Wait for the file to exist.
	file, err := fw.openOrWait(ctx)
	if err != nil {
		log.Printf("[WARN] file watcher: %v", err)
		return
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	ticker := time.NewTicker(fw.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Re-read all available lines.
			for {
				line, err := reader.ReadString('\n')
				if line != "" {
					handler(strings.TrimRight(line, "\r\n"))
				}
				if err != nil {
					break // no more data
				}
			}

			// Check for log rotation (file truncated or recreated).
			info, err := os.Stat(fw.path)
			if err != nil {
				log.Printf("[WARN] stat failed: %v", err)
				continue
			}
			// If file shrank, it was rotated — reopen.
			currentPos, _ := file.Seek(0, 1) // get current position
			if info.Size() < currentPos {
				log.Println("[INFO] log rotation detected, reopening")
				file.Close()
				file, err = os.Open(fw.path)
				if err != nil {
					log.Printf("[WARN] reopen failed: %v", err)
					return
				}
				reader = bufio.NewReader(file)
			}
		}
	}
}

func (fw *fileWatcher) openOrWait(ctx context.Context) (*os.File, error) {
	for {
		file, err := os.Open(fw.path)
		if err == nil {
			return file, nil
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("open %s: %w", fw.path, err)
		}
		log.Printf("[INFO] waiting for %s to be created...", fw.path)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(fw.interval):
		}
	}
}

// redisAdapter wraps go-redis to satisfy rules.RedisCmdRunner.
type redisAdapter struct {
	rdb *redis.Client
}

func (a *redisAdapter) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return a.rdb.Set(ctx, key, value, ttl).Err()
}

func (a *redisAdapter) Ping(ctx context.Context) error {
	return a.rdb.Ping(ctx).Err()
}

// Helpers

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func durationEnvOrDefault(key string, ms int) time.Duration {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Millisecond
		}
	}
	return time.Duration(ms) * time.Millisecond
}

func intEnvOrDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func redactedURL(u string) string {
	opts, err := redis.ParseURL(u)
	if err != nil {
		return "<invalid>"
	}
	if opts.Password == "" {
		return u
	}
	// Return URL without password.
	return fmt.Sprintf("redis://%s@%s/", opts.Username, opts.Addr)
}
