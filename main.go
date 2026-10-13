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
	WebhookPath   string
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

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/webhook"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	return path
}

func loadConfig() Config {
	cfg := Config{
		Port:          env("PORT", "8080"),
		WebhookPath:   normalizePath(env("WEBHOOK_PATH", "/webhook")),
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

func orEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func prettyAction(action string) string {
	return strings.ReplaceAll(action, "_", " ")
}

// utf16Len is the length in UTF-16 code units. signal-cli text styles use that
// unit, so emoji (which sit outside the BMP) count as two.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// signalText is a Signal message plus text-style ranges (start:length:STYLE).
type signalText struct {
	body   string
	styles []string
}

type textBuilder struct {
	b      strings.Builder
	styles []string
	off    int
}

func (w *textBuilder) write(s string) {
	if s == "" {
		return
	}
	w.b.WriteString(s)
	w.off += utf16Len(s)
}

func (w *textBuilder) style(s, style string) {
	if s == "" {
		return
	}
	start := w.off
	w.write(s)
	w.styles = append(w.styles, fmt.Sprintf("%d:%d:%s", start, w.off-start, style))
}

func (w *textBuilder) bold(s string)   { w.style(s, "BOLD") }
func (w *textBuilder) italic(s string) { w.style(s, "ITALIC") }
func (w *textBuilder) mono(s string)   { w.style(s, "MONOSPACE") }
func (w *textBuilder) strike(s string) { w.style(s, "STRIKETHROUGH") }
func (w *textBuilder) nl()             { w.write("\n") }

func (w *textBuilder) header(emoji, title, subject string) {
	if emoji != "" {
		w.write(emoji)
		w.write(" ")
	}
	w.bold(title)
	if subject != "" {
		w.write(" · ")
		w.bold(subject)
	}
	w.nl()
}

func (w *textBuilder) field(label, value string) {
	w.bold(label)
	w.write(": ")
	w.write(value)
	w.nl()
}

func (w *textBuilder) prose(s string, strike bool) {
	if strike {
		w.strike(s)
		return
	}
	w.italic(s)
}

func (w *textBuilder) link(urls ...string) {
	for _, u := range urls {
		if u == "" {
			continue
		}
		if !strings.HasSuffix(w.b.String(), "\n") {
			w.nl()
		}
		w.nl()
		w.write(u)
		return
	}
}

func (w *textBuilder) done() signalText {
	return signalText{
		body:   strings.TrimRight(w.b.String(), "\n"),
		styles: w.styles,
	}
}

func outcomeEmoji(outcome string) string {
	switch outcome {
	case "success", "built":
		return "✅"
	case "failure", "failed", "error", "errored":
		return "❌"
	case "cancelled", "canceled":
		return "🚫"
	case "timed_out":
		return "⏱️"
	case "skipped":
		return "⏭️"
	case "neutral":
		return "⚪"
	case "action_required", "stale":
		return "⚠️"
	default:
		return "⚙️"
	}
}

func prEmoji(action string) string {
	switch action {
	case "merged":
		return "🎉"
	case "opened":
		return "🔀"
	case "reopened":
		return "🔁"
	case "closed":
		return "🚫"
	case "ready_for_review":
		return "👀"
	case "converted_to_draft":
		return "📝"
	default:
		return "🔀"
	}
}

func issueEmoji(action string) string {
	switch action {
	case "opened":
		return "🐛"
	case "reopened":
		return "🔁"
	case "closed":
		return "✅"
	default:
		return "🐛"
	}
}

func buildPushMessage(p pushPayload) signalText {
	refLabel := "Branch"
	ref := strings.TrimPrefix(p.Ref, "refs/heads/")
	emoji := "📤"
	title := "Push"
	if strings.HasPrefix(p.Ref, "refs/tags/") {
		ref = strings.TrimPrefix(p.Ref, "refs/tags/")
		refLabel = "Tag"
		emoji = "🏷️"
		title = "Tag push"
	} else if ref == "" {
		ref = "unknown"
	}

	var w textBuilder
	w.header(emoji, title, repoName(p.Repository))
	w.field(refLabel, ref)
	w.field("By", actorName(p.Pusher, p.Sender))
	w.field("Commits", strconv.Itoa(len(p.Commits)))

	shown := 0
	for _, commit := range p.Commits {
		if shown >= 5 {
			break
		}
		if shown == 0 {
			w.nl()
		}
		shown++
		w.write("• ")
		w.mono(shortSHA(commit.ID))
		w.write(" ")
		w.italic(truncate(firstLine(commit.Message), 150))
		w.nl()
	}
	if len(p.Commits) > shown {
		w.italic(fmt.Sprintf("… and %d more", len(p.Commits)-shown))
		w.nl()
	}

	w.link(p.Compare)
	return w.done()
}

func buildWorkflowRunMessage(p workflowRunPayload) (signalText, bool) {
	if p.Action != "completed" {
		return signalText{}, false
	}

	run := p.WorkflowRun
	title := orEmpty(run.DisplayTitle, run.Name)
	conclusion := orEmpty(run.Conclusion, "unknown")

	var w textBuilder
	w.header(outcomeEmoji(conclusion), "CI", repoName(p.Repository))
	w.field("Workflow", orEmpty(run.Name, "unknown"))
	w.field("Conclusion", conclusion)
	w.field("Branch", orEmpty(run.HeadBranch, "unknown"))
	w.field("By", actorName(run.Actor, p.Sender))
	if title != "" && title != run.Name {
		w.bold("Title")
		w.write(": ")
		w.italic(truncate(title, 150))
		w.nl()
	}
	w.link(run.HTMLURL)
	return w.done(), true
}

func buildCheckRunMessage(p checkRunPayload) (signalText, bool) {
	if p.Action != "completed" {
		return signalText{}, false
	}

	run := p.CheckRun
	conclusion := orEmpty(run.Conclusion, "unknown")

	var w textBuilder
	w.header(outcomeEmoji(conclusion), "Check", repoName(p.Repository))
	w.field("Check", orEmpty(run.Name, "unknown"))
	w.field("Conclusion", conclusion)
	w.field("Branch", orEmpty(run.CheckSuite.HeadBranch, "unknown"))
	w.bold("Commit")
	w.write(": ")
	w.mono(shortSHA(run.HeadSHA))
	w.nl()
	w.field("By", actorName(p.Sender))
	w.link(run.HTMLURL)
	return w.done(), true
}

func buildPageBuildMessage(p pageBuildPayload) (signalText, bool) {
	status := p.Build.Status
	if status != "built" && status != "errored" {
		return signalText{}, false
	}

	var w textBuilder
	w.header(outcomeEmoji(status), "Pages", repoName(p.Repository))
	w.field("Status", status)
	w.bold("Commit")
	w.write(": ")
	w.mono(shortSHA(p.Build.Commit))
	w.nl()
	w.field("By", actorName(p.Build.Pusher, p.Sender))
	if status == "errored" && p.Build.Error.Message != "" {
		w.bold("Error")
		w.write(": ")
		w.italic(truncate(firstLine(p.Build.Error.Message), 200))
		w.nl()
	}
	w.link(p.Repository.HTMLURL)
	return w.done(), true
}

func buildDeploymentStatusMessage(p deploymentStatusPayload) (signalText, bool) {
	state := p.DeploymentStatus.State
	switch state {
	case "success", "failure", "error":
	default:
		return signalText{}, false
	}

	envName := p.DeploymentStatus.Environment
	if envName == "" {
		envName = p.Deployment.Environment
	}

	emoji := outcomeEmoji(state)
	if state == "success" {
		emoji = "🚀"
	}

	var w textBuilder
	w.header(emoji, "Deploy", repoName(p.Repository))
	w.field("Environment", orEmpty(envName, "unknown"))
	w.field("State", state)
	w.bold("Ref")
	w.write(": ")
	w.mono(orEmpty(p.Deployment.Ref, shortSHA(p.Deployment.SHA)))
	w.nl()
	w.field("By", actorName(p.Sender))
	desc := p.DeploymentStatus.Description
	if desc == "" {
		desc = p.Deployment.Description
	}
	if desc != "" {
		w.italic(truncate(firstLine(desc), 200))
		w.nl()
	}
	w.link(p.DeploymentStatus.LogURL, p.DeploymentStatus.TargetURL, p.Repository.HTMLURL)
	return w.done(), true
}

func buildPullRequestMessage(p pullRequestPayload) (signalText, bool) {
	action := p.Action
	switch action {
	case "opened", "reopened", "closed", "ready_for_review", "converted_to_draft":
	default:
		return signalText{}, false
	}

	if action == "closed" && p.PullRequest.Merged {
		action = "merged"
	}

	pr := p.PullRequest
	var w textBuilder
	w.header(prEmoji(action), "PR", repoName(p.Repository))
	w.write("#")
	w.bold(strconv.Itoa(p.Number))
	w.write(" ")
	w.bold(prettyAction(action))
	w.write(": ")
	w.prose(truncate(orEmpty(pr.Title, "untitled"), 150), action == "closed")
	w.nl()
	w.mono(orEmpty(pr.Head.Ref, "?"))
	w.write(" → ")
	w.mono(orEmpty(pr.Base.Ref, "?"))
	w.nl()
	w.field("By", actorName(pr.User, p.Sender))
	w.link(pr.HTMLURL)
	return w.done(), true
}

func buildReleaseMessage(p releasePayload) (signalText, bool) {
	switch p.Action {
	case "published", "released":
	default:
		return signalText{}, false
	}

	rel := p.Release
	kind := "Release"
	emoji := "🏷️"
	if rel.Prerelease {
		kind = "Prerelease"
		emoji = "🧪"
	}
	name := rel.Name
	if name == "" || name == rel.TagName {
		name = rel.TagName
	}

	var w textBuilder
	w.header(emoji, kind, repoName(p.Repository))
	w.bold(orEmpty(rel.TagName, "unknown"))
	if name != "" && name != rel.TagName {
		w.write(" ")
		w.italic("(" + name + ")")
	}
	w.nl()
	w.field("By", actorName(rel.Author, p.Sender))
	w.link(rel.HTMLURL)
	return w.done(), true
}

func buildIssuesMessage(p issuesPayload) (signalText, bool) {
	switch p.Action {
	case "opened", "reopened", "closed":
	default:
		return signalText{}, false
	}

	issue := p.Issue
	var w textBuilder
	w.header(issueEmoji(p.Action), "Issue", repoName(p.Repository))
	w.write("#")
	w.bold(strconv.Itoa(issue.Number))
	w.write(" ")
	w.bold(p.Action)
	w.write(": ")
	w.prose(truncate(orEmpty(issue.Title, "untitled"), 150), p.Action == "closed")
	w.nl()
	w.field("By", actorName(issue.User, p.Sender))
	w.link(issue.HTMLURL)
	return w.done(), true
}

func buildCreateDeleteMessage(event string, p createDeletePayload) signalText {
	emoji := "🌿"
	title := "Created"
	if event == "delete" {
		emoji = "🗑️"
		title = "Deleted"
	} else if p.RefType == "tag" {
		emoji = "🏷️"
	}

	var w textBuilder
	w.header(emoji, title, repoName(p.Repository))
	w.write(orEmpty(p.RefType, "ref"))
	w.write(" ")
	w.mono(orEmpty(p.Ref, "unknown"))
	w.nl()
	w.field("By", actorName(p.Sender))
	w.link(p.Repository.HTMLURL)
	return w.done()
}

func buildStarMessage(p starPayload) (signalText, bool) {
	if p.Action != "created" {
		return signalText{}, false
	}
	var w textBuilder
	w.header("⭐", "Star", repoName(p.Repository))
	w.field("By", actorName(p.Sender))
	w.link(p.Repository.HTMLURL)
	return w.done(), true
}

func buildForkMessage(p forkPayload) signalText {
	var w textBuilder
	w.header("🍴", "Fork", repoName(p.Repository))
	w.field("To", orEmpty(p.Forkee.FullName, "unknown"))
	w.field("By", actorName(p.Sender))
	w.link(p.Forkee.HTMLURL, p.Repository.HTMLURL)
	return w.done()
}

// buildMessage returns a Signal notification and whether one should be sent.
func buildMessage(event string, body []byte) (signalText, bool, error) {
	switch event {
	case "ping":
		return signalText{}, false, nil

	case "push":
		var p pushPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		return buildPushMessage(p), true, nil

	case "workflow_run":
		var p workflowRunPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildWorkflowRunMessage(p)
		return msg, ok, nil

	case "check_run":
		var p checkRunPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildCheckRunMessage(p)
		return msg, ok, nil

	case "page_build":
		var p pageBuildPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildPageBuildMessage(p)
		return msg, ok, nil

	case "deployment_status":
		var p deploymentStatusPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildDeploymentStatusMessage(p)
		return msg, ok, nil

	case "pull_request":
		var p pullRequestPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildPullRequestMessage(p)
		return msg, ok, nil

	case "release":
		var p releasePayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildReleaseMessage(p)
		return msg, ok, nil

	case "issues":
		var p issuesPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildIssuesMessage(p)
		return msg, ok, nil

	case "create", "delete":
		var p createDeletePayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		return buildCreateDeleteMessage(event, p), true, nil

	case "star":
		var p starPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		msg, ok := buildStarMessage(p)
		return msg, ok, nil

	case "fork":
		var p forkPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return signalText{}, false, err
		}
		return buildForkMessage(p), true, nil

	default:
		return signalText{}, false, nil
	}
}

func sendSignal(cfg Config, message signalText) error {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return fmt.Errorf("generate request ID: %w", err)
	}

	params := map[string]any{
		"recipient": []string{cfg.Recipient},
		"message":   message.body,
	}
	if len(message.styles) > 0 {
		params["textStyle"] = message.styles
	}

	requestBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "send",
		"params":  params,
		"id":      hex.EncodeToString(id[:]),
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
	mux.HandleFunc(cfg.WebhookPath, webhook(cfg))
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

	log.Printf("GitHub webhook receiver listening on port %s path %s", cfg.Port, cfg.WebhookPath)
	log.Fatal(server.ListenAndServe())
}
