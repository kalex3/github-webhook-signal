package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const maxBodySize = 1 << 20 // 1 MiB

type Config struct {
	Port        string
	WebhookSecret string
	SignalAPI   string
	Recipient   string
}

type Commit struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

type Payload struct {
	Ref string `json:"ref"`
	Pusher struct {
		Name string `json:"name"`
	} `json:"pusher"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Commits []Commit `json:"commits"`
	Compare string `json:"compare"`
}

type RPCResponse struct {
	Error json.RawMessage `json:"error"`
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func loadConfig() Config {
	cfg := Config{
		Port:          env("PORT", "8080"),
		WebhookSecret: os.Getenv("GITHUB_WEBHOOK_SECRET"),
		SignalAPI:     strings.TrimRight(env("SIGNAL_API", "http://signal-cli:8080"), "/"),
		Recipient:     os.Getenv("SIGNAL_RECIPIENT"),
	}

	if cfg.WebhookSecret == "" || cfg.Recipient == "" {
		log.Fatal("Missing required environment variables: GITHUB_WEBHOOK_SECRET, SIGNAL_RECIPIENT")
	}

	if _, err := strconv.Atoi(cfg.Port); err != nil {
		log.Fatal("PORT must be a valid port number")
	}

	return cfg
}

func verifySignature(secret string, body []byte, signature string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}

	provided, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil || len(provided) != sha256.Size {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)

	return hmac.Equal(provided, mac.Sum(nil))
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return strings.TrimSuffix(line, "\r")
}

func buildMessage(p Payload) string {
	repo := p.Repository.FullName
	if repo == "" {
		repo = "unknown repository"
	}

	branch := strings.TrimPrefix(p.Ref, "refs/heads/")
	if branch == "" {
		branch = "unknown"
	}

	pusher := p.Pusher.Name
	if pusher == "" {
		pusher = "unknown"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "GitHub push: %s\nBranch: %s\nBy: %s\nCommits: %d",
		repo, branch, pusher, len(p.Commits))

	for i, commit := range p.Commits {
		if i >= 5 {
			break
		}

		message := []rune(firstLine(commit.Message))
		if len(message) > 150 {
			message = message[:150]
		}

		id := commit.ID
		if len(id) > 7 {
			id = id[:7]
		}
		if id == "" {
			id = "unknown"
		}

		if i == 0 {
			b.WriteString("\n\n")
		} else {
			b.WriteByte('\n')
		}

		fmt.Fprintf(&b, "- %s %s", id, string(message))
	}

	if p.Compare != "" {
		b.WriteString("\n\n")
		b.WriteString(p.Compare)
	}

	return b.String()
}

func sendSignal(cfg Config, message string) error {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return fmt.Errorf("generate request ID: %w", err)
	}

	requestBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "send",
		"params": map[string]any{
			"recipient": []string{cfg.Recipient},
			"message":   message,
		},
		"id": hex.EncodeToString(id[:]),
	})
	if err != nil {
		return fmt.Errorf("encode RPC request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, cfg.SignalAPI+"/api/v1/rpc",
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return fmt.Errorf("create RPC request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Signal API request: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read Signal API response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Signal API HTTP %d: %s", resp.StatusCode, responseBody)
	}

	var rpc RPCResponse
	if err := json.Unmarshal(responseBody, &rpc); err != nil {
		return fmt.Errorf("invalid Signal API JSON: %w", err)
	}

	if len(rpc.Error) > 0 && string(rpc.Error) != "null" {
		return fmt.Errorf("Signal JSON-RPC error: %s", rpc.Error)
	}

	return nil
}

func webhook(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "Expected application/json", http.StatusUnsupportedMediaType)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
		if err != nil {
			http.Error(w, "Invalid or oversized request body", http.StatusBadRequest)
			return
		}

		if !verifySignature(cfg.WebhookSecret, body, r.Header.Get("X-Hub-Signature-256")) {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		if r.Header.Get("X-GitHub-Event") != "push" {
			http.Error(w, "Event ignored", http.StatusOK)
			return
		}

		var p Payload
		if err := json.Unmarshal(body, &p); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if err := sendSignal(cfg, buildMessage(p)); err != nil {
			log.Printf("Signal delivery failed: %v", err)
			http.Error(w, "Signal delivery failed", http.StatusBadGateway)
			return
		}

		log.Printf("Signal notification sent for %s:%s",
			p.Repository.FullName, strings.TrimPrefix(p.Ref, "refs/heads/"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Notification sent"))
	}
}

func main() {
	cfg := loadConfig()

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", webhook(cfg))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	server := &http.Server{
		Addr:              "0.0.0.0:" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("GitHub webhook receiver listening on port %s", cfg.Port)
	log.Fatal(server.ListenAndServe())
}
