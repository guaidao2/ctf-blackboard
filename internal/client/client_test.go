package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guaidao2/ctf-blackboard/internal/protocol"
	"github.com/guaidao2/ctf-blackboard/internal/secure"
	"github.com/guaidao2/ctf-blackboard/internal/server"
)

const testPassword = "correct-horse-battery-staple"

func startTestServer(t *testing.T) server.Info {
	t.Helper()
	srv, err := server.New(server.Config{
		Listen:          "127.0.0.1:0",
		DataDir:         t.TempDir(),
		Password:        testPassword,
		ServerName:      "test board",
		Motd:            "test motd",
		SlotLimit:       2,
		TotalChallenges: 5,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	info, err := srv.Start()
	if err != nil {
		t.Fatalf("Start server: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Close(ctx)
	})
	return info
}

func TestRemoteRoundTrip(t *testing.T) {
	info := startTestServer(t)
	events := make(chan protocol.Envelope, 64)
	cli, err := Dial(context.Background(), Config{
		URL:      info.URL,
		Pin:      info.Pin,
		Nick:     "alice",
		Password: testPassword,
		OnEvent:  func(env protocol.Envelope) { events <- env },
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cli.Close()

	raw, err := cli.Request(protocol.CmdStateGet, struct{}{}, 5*time.Second)
	if err != nil {
		t.Fatalf("state.get: %v", err)
	}
	var snap protocol.Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatal(err)
	}
	if snap.You != "alice" || snap.Board.TotalChallenges != 5 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}

	if _, err := cli.Request(protocol.CmdChatSend, protocol.ChatSendArgs{Text: "hello"}, 5*time.Second); err != nil {
		t.Fatalf("chat.send: %v", err)
	}
	deadline := time.After(3 * time.Second)
waitLoop:
	for {
		select {
		case env := <-events:
			if env.Name == protocol.EventMessage {
				var msg protocol.MessageEvent
				if err := protocol.Decode(env, &msg); err != nil {
					t.Fatal(err)
				}
				if msg.Message.Text != "hello" {
					t.Fatalf("unexpected message: %+v", msg.Message)
				}
				break waitLoop
			}
		case <-deadline:
			t.Fatal("did not receive chat message event")
		}
	}

	// Many concurrent requests must serialize their encrypted frames; a
	// sequence mismatch would make the server drop the session.
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cli.Request(protocol.CmdStateGet, struct{}{}, 5*time.Second); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent state.get: %v", err)
	}

	raw, err = cli.Request(protocol.CmdSolverAdd, protocol.SolverAddArgs{
		Challenge: "ezsql", Nick: "alice", Writeup: "union select",
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("solver.add: %v", err)
	}
	var added protocol.SolverResult
	if err := json.Unmarshal(raw, &added); err != nil {
		t.Fatal(err)
	}
	if added.Solver.Challenge != "ezsql" || !added.Solver.HasWriteup {
		t.Fatalf("unexpected solver: %+v", added.Solver)
	}
	raw, err = cli.Request(protocol.CmdSolverGet, protocol.IDArgs{ID: added.Solver.ID}, 5*time.Second)
	if err != nil {
		t.Fatalf("solver.get: %v", err)
	}
	var got protocol.SolverResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Solver.Writeup, "union") {
		t.Fatalf("writeup missing: %q", got.Solver.Writeup)
	}
}

func TestBridgeHTTPExportAndReconnect(t *testing.T) {
	info := startTestServer(t)
	bridge, err := NewBridge(Options{
		Token:          "test-local-token",
		Listen:         "127.0.0.1:0",
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	uiURL, err := bridge.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = bridge.Close(ctx)
	})
	base := strings.Split(uiURL, "/#")[0]
	const token = "test-local-token"

	// Every API call requires the local token.
	resp, err := http.Get(base + "/api/session")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("session without token = %d, want 403", resp.StatusCode)
	}

	status, body := postJSON(t, base, token, "/api/login", LoginRequest{
		Server: info.URL, Pin: info.Pin, Nick: "alice", Password: testPassword,
	})
	if status != http.StatusOK {
		t.Fatalf("login = %d: %s", status, body)
	}
	var login struct {
		OK       bool            `json:"ok"`
		Snapshot json.RawMessage `json:"snapshot"`
		Error    string          `json:"error"`
	}
	if err := json.Unmarshal(body, &login); err != nil {
		t.Fatal(err)
	}
	if !login.OK || len(login.Snapshot) == 0 {
		t.Fatalf("login failed: %s", body)
	}

	status, body = postJSON(t, base, token, "/api/command", map[string]any{
		"cmd": protocol.CmdSolverAdd,
		"args": map[string]any{
			"challenge": "ezsql",
			"nick":      "alice",
			"writeup":   "union select flag",
		},
	})
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"ok":true`)) {
		t.Fatalf("solver.add = %d: %s", status, body)
	}

	req, _ := http.NewRequest(http.MethodGet, base+"/api/export?format=md", nil)
	req.Header.Set("X-CTFBB-Token", token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	exported, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d: %s", resp.StatusCode, exported)
	}
	if !bytes.Contains(exported, []byte("ezsql")) || !bytes.Contains(exported, []byte("union select flag")) {
		t.Fatalf("export missing content:\n%s", exported)
	}

	// The SSE endpoint pushes the current snapshot immediately.
	sseCtx, cancelSSE := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelSSE()
	sseReq, _ := http.NewRequestWithContext(sseCtx, http.MethodGet, base+"/api/events?token="+token, nil)
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(sseResp.Body)
	foundSnapshot := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, `"name":"snapshot"`) {
			foundSnapshot = true
			break
		}
	}
	sseResp.Body.Close()
	if !foundSnapshot {
		t.Fatal("SSE did not send an initial snapshot")
	}

	// Simulate a dropped connection and wait for the bridge to reconnect.
	s := bridge.currentSession()
	if s == nil {
		t.Fatal("no session after login")
	}
	s.mu.Lock()
	cli := s.cli
	s.mu.Unlock()
	if cli == nil {
		t.Fatal("no remote client")
	}
	_ = cli.Close()
	waitStatus(t, base, token, statusReconnecting, 3*time.Second)
	waitStatus(t, base, token, statusOnline, 8*time.Second)

	// Logout clears the session while keeping the local GUI up.
	status, body = postJSON(t, base, token, "/api/logout", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("logout = %d: %s", status, body)
	}
	if bridge.currentSession() != nil {
		t.Fatal("session still present after logout")
	}
}

func postJSON(t *testing.T, base, token, path string, payload any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CTFBB-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func waitStatus(t *testing.T, base, token, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, base+"/api/session", nil)
		req.Header.Set("X-CTFBB-Token", token)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			var data struct {
				Status string `json:"status"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&data)
			resp.Body.Close()
			if data.Status == want {
				return
			}
		}
		time.Sleep(80 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for bridge status %q", want)
}

func TestKnownHostsRememberAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts.json")
	k, err := LoadKnownHosts(path)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := secure.NormalizeFingerprint(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Remember("wss://example:8443/ws", pin); err != nil {
		t.Fatal(err)
	}
	k2, err := LoadKnownHosts(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := k2.Lookup("wss://example:8443/ws")
	if !ok || got != pin {
		t.Fatalf("known_hosts lookup = %q, %v; want %q", got, ok, pin)
	}
}

func TestProbeFingerprint(t *testing.T) {
	info := startTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := ProbeFingerprint(ctx, info.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got != info.Pin {
		t.Fatalf("probe fingerprint = %s, want %s", got, info.Pin)
	}
}

func TestBridgeTrustOnFirstUse(t *testing.T) {
	info := startTestServer(t)
	knownPath := filepath.Join(t.TempDir(), "known_hosts.json")

	b1, err := NewBridge(Options{
		Token:          "tofu-token",
		Listen:         "127.0.0.1:0",
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		KnownHostsPath: knownPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	uiURL, err := b1.Start()
	if err != nil {
		t.Fatal(err)
	}
	base := strings.Split(uiURL, "/#")[0]
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = b1.Close(ctx)
	})

	status, body := postJSON(t, base, "tofu-token", "/api/login", LoginRequest{
		Server: info.URL, Nick: "alice", Password: testPassword,
	})
	if status != http.StatusPreconditionRequired {
		t.Fatalf("first login without pin = %d, want 428: %s", status, body)
	}
	var trust struct {
		TrustRequired bool   `json:"trustRequired"`
		Pin           string `json:"pin"`
		Server        string `json:"server"`
	}
	if err := json.Unmarshal(body, &trust); err != nil {
		t.Fatal(err)
	}
	if !trust.TrustRequired || trust.Pin != info.Pin || trust.Server != info.URL {
		t.Fatalf("unexpected trust prompt: %+v", trust)
	}

	status, body = postJSON(t, base, "tofu-token", "/api/login", LoginRequest{
		Server: info.URL, Pin: trust.Pin, Nick: "alice", Password: testPassword,
	})
	if status != http.StatusOK {
		t.Fatalf("trusted login = %d: %s", status, body)
	}

	known, err := LoadKnownHosts(knownPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := known.Lookup(info.URL); !ok || got != trust.Pin {
		t.Fatalf("fingerprint was not remembered: %q %v", got, ok)
	}

	// Log out, then a fresh bridge with the same known_hosts should not ask
	// again even though no pin is supplied.
	postJSON(t, base, "tofu-token", "/api/logout", map[string]any{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = b1.Close(ctx)
	cancel()

	b2, err := NewBridge(Options{
		Token:          "tofu-token-2",
		Listen:         "127.0.0.1:0",
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		KnownHostsPath: knownPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	uiURL2, err := b2.Start()
	if err != nil {
		t.Fatal(err)
	}
	base2 := strings.Split(uiURL2, "/#")[0]
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = b2.Close(ctx)
	})
	status, body = postJSON(t, base2, "tofu-token-2", "/api/login", LoginRequest{
		Server: info.URL, Nick: "bob", Password: testPassword,
	})
	if status != http.StatusOK {
		t.Fatalf("remembered login = %d: %s", status, body)
	}
}

func TestKnownHostsCanonicalizesURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts.json")
	k, err := LoadKnownHosts(path)
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := secure.NormalizeFingerprint(strings.Repeat("ab", 32))
	if err := k.Remember("wss://EXAMPLE:8443/ws/", pin); err != nil {
		t.Fatal(err)
	}
	if got, ok := k.Lookup("wss://example:8443/ws"); !ok || got != pin {
		t.Fatalf("canonical lookup = %q, %v; want %q", got, ok, pin)
	}
}

func TestKnownHostsRejectsUnknownVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts.json")
	if err := os.WriteFile(path, []byte(`{"version":99,"hosts":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKnownHosts(path); err == nil {
		t.Fatal("unknown known_hosts version was accepted")
	}
}

func TestBridgeMovesCorruptKnownHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts.json")
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := NewBridge(Options{
		Token:          "corrupt-token",
		Listen:         "127.0.0.1:0",
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		KnownHostsPath: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	moved, _ := filepath.Glob(path + ".corrupt-*")
	if len(moved) != 1 {
		t.Fatalf("corrupt known_hosts was not preserved: %v", moved)
	}
	if b.known.Path() != path {
		t.Fatalf("known_hosts path = %q", b.known.Path())
	}
}

func TestBridgeRejectsChangedFingerprint(t *testing.T) {
	info := startTestServer(t)
	knownPath := filepath.Join(t.TempDir(), "known_hosts.json")
	k, err := LoadKnownHosts(knownPath)
	if err != nil {
		t.Fatal(err)
	}
	wrong := secure.FormatFingerprint(bytes.Repeat([]byte{0x11}, 32))
	if err := k.Remember(info.URL, wrong); err != nil {
		t.Fatal(err)
	}

	b, err := NewBridge(Options{
		Token:          "changed-token",
		Listen:         "127.0.0.1:0",
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		KnownHostsPath: knownPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	uiURL, err := b.Start()
	if err != nil {
		t.Fatal(err)
	}
	base := strings.Split(uiURL, "/#")[0]
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = b.Close(ctx)
	})

	status, body := postJSON(t, base, "changed-token", "/api/login", LoginRequest{
		Server: info.URL, Nick: "alice", Password: testPassword,
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("changed fingerprint = %d, want 401: %s", status, body)
	}
	if !bytes.Contains(body, []byte("证书指纹不匹配")) || !bytes.Contains(body, []byte("known_hosts.json")) {
		t.Fatalf("mismatch error is not actionable: %s", body)
	}

	// An explicit pin must not silently overwrite the trusted one.
	status, body = postJSON(t, base, "changed-token", "/api/login", LoginRequest{
		Server: info.URL, Pin: info.Pin, Nick: "alice", Password: testPassword,
	})
	if status != http.StatusUnauthorized || !bytes.Contains(body, []byte("记录的指纹")) {
		t.Fatalf("explicit pin overwrote trusted pin: %d %s", status, body)
	}

	after, err := LoadKnownHosts(knownPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := after.Lookup(info.URL); !ok || got != wrong {
		t.Fatalf("remembered pin changed after a failed login: %q %v", got, ok)
	}
}

func TestBridgeRejectsNonLoopbackUI(t *testing.T) {
	b, err := NewBridge(Options{
		Token:          "loopback-token",
		Listen:         "0.0.0.0:0",
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Start(); err == nil {
		t.Fatal("non-loopback GUI was accepted without --allow-remote-ui")
	}
}
