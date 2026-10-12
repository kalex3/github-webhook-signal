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
	Port          string
	WebhookSecret string
	SignalAPI     string
	Recipient     string
}

type repository struct {
	FullName string `json:"full_name"`
	HTMLURL  string `json:"html_url"`
}

type actor struct {
	Login string `json:"login"`
	Name  string `json:"name"`
}

type Commit struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

type pushPayload struct {
	Ref        string     `json:"ref"`
	Compare    string     `json:"compare"`
	Pusher     actor      `json:"pusher"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
	Commits    []Commit   `json:"commits"`
}

type workflowRunPayload struct {
	Action      string `json:"action"`
	WorkflowRun struct {
		Name         string `json:"name"`
		HTMLURL      string `json:"html_url"`
		Status       string `json:"status"`
		Conclusion   string `json:"conclusion"`
		Event        string `json:"event"`
		HeadBranch   string `json:"head_branch"`
		DisplayTitle string `json:"display_title"`
		Actor        actor  `json:"actor"`
	} `json:"workflow_run"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type checkRunPayload struct {
	Action   string `json:"action"`
	CheckRun struct {
		Name       string `json:"name"`
		HTMLURL    string `json:"html_url"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		HeadSHA    string `json:"head_sha"`
		CheckSuite struct {
			HeadBranch string `json:"head_branch"`
		} `json:"check_suite"`
	} `json:"check_run"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type pageBuildPayload struct {
	Build struct {
		Status string `json:"status"`
		Error  struct {
			Message string `json:"message"`
		} `json:"error"`
		Commit string `json:"commit"`
		Pusher actor  `json:"pusher"`
	} `json:"build"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type deploymentStatusPayload struct {
	DeploymentStatus struct {
		State       string `json:"state"`
		Description string `json:"description"`
		TargetURL   string `json:"target_url"`
		Environment string `json:"environment"`
		LogURL      string `json:"log_url"`
	} `json:"deployment_status"`
	Deployment struct {
		Environment string `json:"environment"`
		Ref         string `json:"ref"`
		SHA         string `json:"sha"`
		Description string `json:"description"`
	} `json:"deployment"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type pullRequestPayload struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		Title   string `json:"title"`
		HTMLURL string `json:"html_url"`
		Merged  bool   `json:"merged"`
		User    actor  `json:"user"`
		Head    struct {
			Ref string `json:"ref"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	} `json:"pull_request"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type releasePayload struct {
	Action  string `json:"action"`
	Release struct {
		TagName    string `json:"tag_name"`
		Name       string `json:"name"`
		HTMLURL    string `json:"html_url"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Author     actor  `json:"author"`
	} `json:"release"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type issuesPayload struct {
	Action string `json:"action"`
	Issue  struct {
		Number  int    `json:"number"`
		Title   string `json:"title"`
		HTMLURL string `json:"html_url"`
		User    actor  `json:"user"`
	} `json:"issue"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type createDeletePayload struct {
	Ref        string     `json:"ref"`
	RefType    string     `json:"ref_type"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type starPayload struct {
	Action     string     `json:"action"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
}

type forkPayload struct {
	Forkee struct {
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	} `json:"forkee"`
	Sender     actor      `json:"sender"`
	Repository repository `json:"repository"`
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

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}

func shortSHA(id string) string {
	if len(id) > 7 {
		return id[:7]
	}
	if id == "" {
		return "unknown"
	}
	return id
}

func repoName(r repository) string {
	if r.FullName == "" {
		return "unknown repository"
	}
	return r.FullName
}

func actorName(a ...actor) string {
	for _, person := range a {
		if person.Name != "" {
			return person.Name
		}
		if person.Login != "" {
			return person.Login
		}
	}
	return "unknown"
}

func appendURL(b *strings.Builder, urls ...string) {
	for _, u := range urls {
		if u != "" {
			b.WriteString("\n\n")
			b.WriteString(u)
			return
		}
	}
}

func orEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func buildPushMessage(p pushPayload) string {
	branch := strings.TrimPrefix(p.Ref, "refs/heads/")
	if strings.HasPrefix(p.Ref, "refs/tags/") {
		branch = "tag " + strings.TrimPrefix(p.Ref, "refs/tags/")
	} else if branch == "" {
		branch = "unknown"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "GitHub push: %s\nBranch: %s\nBy: %s\nCommits: %d",
		repoName(p.Repository), branch, actorName(p.Pusher, p.Sender), len(p.Commits))

	for i, commit := range p.Commits {
		if i >= 5 {
			break
		}
		if i == 0 {
			b.WriteString("\n\n")
		} else {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "- %s %s", shortSHA(commit.ID), truncate(firstLine(commit.Message), 150))
	}

	appendURL(&b, p.Compare)
	return b.String()
}

func buildWorkflowRunMessage(p workflowRunPayload) (string, bool) {
	if p.Action != "completed" {
		return "", false
	}

	run := p.WorkflowRun
	title := orEmpty(run.DisplayTitle, run.Name)
	var b strings.Builder
	fmt.Fprintf(&b, "GitHub CI: %s\nWorkflow: %s\nConclusion: %s\nBranch: %s\nBy: %s",
		repoName(p.Repository),
		orEmpty(run.Name, "unknown"),
		orEmpty(run.Conclusion, "unknown"),
		orEmpty(run.HeadBranch, "unknown"),
		actorName(run.Actor, p.Sender),
	)
	if title != "" && title != run.Name {
		fmt.Fprintf(&b, "\nTitle: %s", truncate(title, 150))
	}
	appendURL(&b, run.HTMLURL)
	return b.String(), true
}

func buildCheckRunMessage(p checkRunPayload) (string, bool) {
	if p.Action != "completed" {
		return "", false
	}

	run := p.CheckRun
	var b strings.Builder
	fmt.Fprintf(&b, "GitHub check: %s\nCheck: %s\nConclusion: %s\nBranch: %s\nCommit: %s\nBy: %s",
		repoName(p.Repository),
		orEmpty(run.Name, "unknown"),
		orEmpty(run.Conclusion, "unknown"),
		orEmpty(run.CheckSuite.HeadBranch, "unknown"),
		shortSHA(run.HeadSHA),
		actorName(p.Sender),
	)
	appendURL(&b, run.HTMLURL)
	return b.String(), true
}

func buildPageBuildMessage(p pageBuildPayload) (string, bool) {
	status := p.Build.Status
	if status != "built" && status != "errored" {
		return "", false
	}

	var b strings.Builder
	fmt.Fprintf(&b, "GitHub Pages: %s\nStatus: %s\nCommit: %s\nBy: %s",
		repoName(p.Repository),
		status,
		shortSHA(p.Build.Commit),
		actorName(p.Build.Pusher, p.Sender),
	)
	if status == "errored" && p.Build.Error.Message != "" {
		fmt.Fprintf(&b, "\nError: %s", truncate(firstLine(p.Build.Error.Message), 200))
	}
	appendURL(&b, p.Repository.HTMLURL)
	return b.String(), true
}

func buildDeploymentStatusMessage(p deploymentStatusPayload) (string, bool) {
	state := p.DeploymentStatus.State
	switch state {
	case "success", "failure", "error":
	default:
		return "", false
	}

	envName := p.DeploymentStatus.Environment
	if envName == "" {
		envName = p.Deployment.Environment
	}

	var b strings.Builder
	fmt.Fprintf(&b, "GitHub deploy: %s\nEnvironment: %s\nState: %s\nRef: %s\nBy: %s",
		repoName(p.Repository),
		orEmpty(envName, "unknown"),
		state,
		orEmpty(p.Deployment.Ref, shortSHA(p.Deployment.SHA)),
		actorName(p.Sender),
	)
	desc := p.DeploymentStatus.Description
	if desc == "" {
		desc = p.Deployment.Description
	}
	if desc != "" {
		fmt.Fprintf(&b, "\n%s", truncate(firstLine(desc), 200))
	}
	appendURL(&b, p.DeploymentStatus.LogURL, p.DeploymentStatus.TargetURL, p.Repository.HTMLURL)
	return b.String(), true
}

func buildPullRequestMessage(p pullRequestPayload) (string, bool) {
	action := p.Action
	switch action {
	case "opened", "reopened", "closed", "ready_for_review", "converted_to_draft":
	default:
		return "", false
	}

	if action == "closed" && p.PullRequest.Merged {
		action = "merged"
	}

	pr := p.PullRequest
	var b strings.Builder
	fmt.Fprintf(&b, "GitHub PR: %s\n#%d %s: %s\n%s → %s\nBy: %s",
		repoName(p.Repository),
		p.Number,
		action,
		truncate(orEmpty(pr.Title, "untitled"), 150),
		orEmpty(pr.Head.Ref, "?"),
		orEmpty(pr.Base.Ref, "?"),
		actorName(pr.User, p.Sender),
	)
	appendURL(&b, pr.HTMLURL)
	return b.String(), true
}

func buildReleaseMessage(p releasePayload) (string, bool) {
	switch p.Action {
	case "published", "released":
	default:
		return "", false
	}

	rel := p.Release
	kind := "release"
	if rel.Prerelease {
		kind = "prerelease"
	}
	name := rel.Name
	if name == "" || name == rel.TagName {
		name = rel.TagName
	} else {
		name = rel.TagName + " (" + name + ")"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "GitHub %s: %s\n%s\nBy: %s",
		kind,
		repoName(p.Repository),
		orEmpty(name, "unknown"),
		actorName(rel.Author, p.Sender),
	)
	appendURL(&b, rel.HTMLURL)
	return b.String(), true
}

func buildIssuesMessage(p issuesPayload) (string, bool) {
	switch p.Action {
	case "opened", "reopened", "closed":
	default:
		return "", false
	}

	issue := p.Issue
	var b strings.Builder
	fmt.Fprintf(&b, "GitHub issue: %s\n#%d %s: %s\nBy: %s",
		repoName(p.Repository),
		issue.Number,
		p.Action,
		truncate(orEmpty(issue.Title, "untitled"), 150),
		actorName(issue.User, p.Sender),
	)
	appendURL(&b, issue.HTMLURL)
	return b.String(), true
}

func buildCreateDeleteMessage(event string, p createDeletePayload) string {
	var b strings.Builder
	fmt.Fprintf(&b, "GitHub %s: %s\n%s %s\nBy: %s",
		event,
		repoName(p.Repository),
		orEmpty(p.RefType, "ref"),
		orEmpty(p.Ref, "unknown"),
		actorName(p.Sender),
	)
	appendURL(&b, p.Repository.HTMLURL)
	return b.String()
}

func buildStarMessage(p starPayload) (string, bool) {
	if p.Action != "created" {
		return "", false
	}
	var b strings.Builder
	fmt.Fprintf(&b, "GitHub star: %s\nBy: %s", repoName(p.Repository), actorName(p.Sender))
	appendURL(&b, p.Repository.HTMLURL)
	return b.String(), true
}

func buildForkMessage(p forkPayload) string {
	var b strings.Builder
	fmt.Fprintf(&b, "GitHub fork: %s\nTo: %s\nBy: %s",
		repoName(p.Repository),
		orEmpty(p.Forkee.FullName, "unknown"),
		actorName(p.Sender),
	)
	appendURL(&b, p.Forkee.HTMLURL, p.Repository.HTMLURL)
	return b.String()
}

// buildMessage returns a Signal notification body and whether one should be sent.
func buildMessage(event string, body []byte) (string, bool, error) {
	switch event {
	case "ping":
		return "", false, nil

	case "push":
		var p pushPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return "", false, err
		}
		return buildPushMessage(p), true, nil

	case "workflow_run":
		var p workflowRunPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return "", false, err
		}
		msg, ok := buildWorkflowRunMessage(p)
		return msg, ok, nil

	case "check_run":
		var p checkRunPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return "", false, err
		}
		msg, ok := buildCheckRunMessage(p)
		return msg, ok, nil

	case "page_build":
		var p pageBuildPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return "", false, err
		}
		msg, ok := buildPageBuildMessage(p)
		return msg, ok, nil

	case "deployment_status":
		var p deploymentStatusPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return "", false, err
		}
		msg, ok := buildDeploymentStatusMessage(p)
		return msg, ok, nil

	case "pull_request":
		var p pullRequestPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return "", false, err
		}
		msg, ok := buildPullRequestMessage(p)
		return msg, ok, nil

	case "release":
		var p releasePayload
		if err := json.Unmarshal(body, &p); err != nil {
			return "", false, err
		}
		msg, ok := buildReleaseMessage(p)
		return msg, ok, nil

	case "issues":
		var p issuesPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return "", false, err
		}
		msg, ok := buildIssuesMessage(p)
		return msg, ok, nil

	case "create", "delete":
		var p createDeletePayload
		if err := json.Unmarshal(body, &p); err != nil {
			return "", false, err
		}
		return buildCreateDeleteMessage(event, p), true, nil

	case "star":
		var p starPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return "", false, err
		}
		msg, ok := buildStarMessage(p)
		return msg, ok, nil

	case "fork":
		var p forkPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return "", false, err
		}
		return buildForkMessage(p), true, nil

	default:
		return "", false, nil
	}
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

		event := r.Header.Get("X-GitHub-Event")
		message, notify, err := buildMessage(event, body)
		if err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if !notify {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Event ignored"))
			return
		}

		if err := sendSignal(cfg, message); err != nil {
			log.Printf("Signal delivery failed for %s: %v", event, err)
			http.Error(w, "Signal delivery failed", http.StatusBadGateway)
			return
		}

		log.Printf("Signal notification sent for %s", event)
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
