package client

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/ctf-blackboard/internal/model"
	"github.com/guaidao2/ctf-blackboard/internal/protocol"
	"github.com/guaidao2/ctf-blackboard/internal/secure"
)

var Version = "1.1.0"

const (
	statusConnecting   = "connecting"
	statusOnline       = "online"
	statusReconnecting = "reconnecting"
	statusOffline      = "offline"
	statusKicked       = "kicked"
)

// Prefill is what the login form starts with, sourced from CLI flags or
// server-info.txt. No password is ever kept here.
type Prefill struct {
	URL  string `json:"url"`
	Pin  string `json:"pin"`
	Nick string `json:"nick"`
}

type Options struct {
	Prefill            Prefill
	Token              string
	Listen             string
	Logger             *slog.Logger
	KnownHostsPath     string
	AllowNonLoopbackUI bool
}

// TrustRequiredError means this server has no remembered fingerprint yet. The
// caller should show the fingerprint to the user and retry with Pin set.
type TrustRequiredError struct {
	Server string
	Pin    string
}

func (e *TrustRequiredError) Error() string {
	return "首次连接，需要确认服务器指纹"
}

// Bridge owns the remote session and serves the local browser GUI. The browser
// never talks to the remote server directly.
type Bridge struct {
	opts  Options
	log   *slog.Logger
	web   fs.FS
	token string
	known *KnownHosts

	mu      sync.Mutex
	loginMu sync.Mutex
	sess    *session
	prefill Prefill
	subs    map[int]chan []byte
	nextSub int

	srv       *http.Server
	ln        net.Listener
	addr      string
	quit      chan struct{}
	quitOnce  sync.Once
	closeOnce sync.Once
}

type LoginRequest struct {
	Server   string `json:"server"`
	Pin      string `json:"pin"`
	Nick     string `json:"nick"`
	Password string `json:"password"`
}

type session struct {
	bridge *Bridge
	cfg    Config

	mu        sync.Mutex
	cli       *Client
	snapshot  protocol.Snapshot
	status    string
	lastErr   string
	buffering bool
	buffer    []protocol.Envelope
	stop      chan struct{}
	stopped   bool
}

type localEvent struct {
	Name string          `json:"name"`
	Data json.RawMessage `json:"data,omitempty"`
}

type statusEvent struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// NewBridge creates the local bridge. Call Start to bind the loopback port.
func NewBridge(opts Options) (*Bridge, error) {
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:0"
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	token := strings.TrimSpace(opts.Token)
	if token == "" {
		token = randomToken()
	}
	knownPath := strings.TrimSpace(opts.KnownHostsPath)
	if knownPath == "" {
		if p, err := DefaultKnownHostsPath(); err == nil {
			knownPath = p
		} else {
			opts.Logger.Warn("cannot locate known_hosts; fingerprints will be asked every time", "err", err)
		}
	}
	known, err := LoadKnownHosts(knownPath)
	if err != nil {
		moved := ""
		if knownPath != "" {
			corrupt := fmt.Sprintf("%s.corrupt-%d", knownPath, time.Now().Unix())
			if renameErr := os.Rename(knownPath, corrupt); renameErr == nil {
				moved = corrupt
			}
		}
		opts.Logger.Warn("cannot read known_hosts; moved the corrupt file aside", "file", knownPath, "moved", moved, "err", err)
		known = newKnownHosts(knownPath)
	}
	return &Bridge{
		opts:    opts,
		log:     opts.Logger,
		web:     webRoot(),
		token:   token,
		known:   known,
		prefill: opts.Prefill,
		subs:    map[int]chan []byte{},
		quit:    make(chan struct{}),
	}, nil
}

// Start binds the local HTTP server and returns the browser URL (including the
// one-time local token in the fragment).
func (b *Bridge) Start() (string, error) {
	ln, err := net.Listen("tcp", b.opts.Listen)
	if err != nil {
		return "", fmt.Errorf("本地 GUI 端口监听失败：%w", err)
	}
	b.addr = ln.Addr().String()
	if !loopbackHost(b.addr) && !b.opts.AllowNonLoopbackUI {
		_ = ln.Close()
		return "", fmt.Errorf("本地 GUI 只允许监听回环地址；如确需远程访问，请显式加 --allow-remote-ui")
	}
	b.ln = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/api/prefill", b.auth(b.handlePrefill))
	mux.HandleFunc("/api/login", b.auth(b.handleLogin))
	mux.HandleFunc("/api/session", b.auth(b.handleSession))
	mux.HandleFunc("/api/command", b.auth(b.handleCommand))
	mux.HandleFunc("/api/logout", b.auth(b.handleLogout))
	mux.HandleFunc("/api/export", b.auth(b.handleExport))
	mux.HandleFunc("/api/events", b.auth(b.handleEvents))
	mux.HandleFunc("/api/health", b.auth(b.handleHealth))
	mux.HandleFunc("/api/quit", b.auth(b.handleQuit))
	mux.Handle("/", http.FileServer(http.FS(b.web)))

	b.srv = &http.Server{
		Handler:           b.securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		err := b.srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			b.log.Error("local GUI server stopped", "err", err)
		}
	}()
	return b.URL(), nil
}

// URL is the browser address with the local token in the fragment.
func (b *Bridge) URL() string {
	host, port, err := net.SplitHostPort(b.addr)
	if err != nil {
		host, port = b.addr, ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	addr := host
	if port != "" {
		addr = net.JoinHostPort(host, port)
	}
	return "http://" + addr + "/#" + b.token
}

func (b *Bridge) Token() string { return b.token }

func (b *Bridge) Quit() <-chan struct{} { return b.quit }

// Close logs out, stops the local server and unblocks Quit.
func (b *Bridge) Close(ctx context.Context) error {
	b.closeOnce.Do(func() {
		b.Logout()
		b.quitOnce.Do(func() { close(b.quit) })
		if b.srv != nil {
			_ = b.srv.Shutdown(ctx)
		}
	})
	return nil
}

func (b *Bridge) getPrefill() Prefill {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.prefill
}

func (b *Bridge) currentSession() *session {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sess
}

// Login replaces any existing session with a new remote connection.
func (b *Bridge) Login(ctx context.Context, req LoginRequest) (json.RawMessage, error) {
	b.loginMu.Lock()
	defer b.loginMu.Unlock()

	req.Server = strings.TrimSpace(req.Server)
	req.Pin = strings.TrimSpace(req.Pin)
	req.Nick = strings.TrimSpace(req.Nick)
	if req.Server == "" || req.Nick == "" || req.Password == "" {
		return nil, errors.New("服务器、昵称、密码都要填")
	}

	// Explicit pin (server-info.txt / advanced) wins, but it must not
	// silently override a different fingerprint already trusted for this
	// server. Recovery is deliberately explicit: delete the known_hosts entry.
	if req.Pin != "" {
		canonical, err := secure.NormalizeFingerprint(req.Pin)
		if err != nil {
			return nil, fmt.Errorf("证书指纹无效：%w", err)
		}
		req.Pin = canonical
		if saved, ok := b.known.Lookup(req.Server); ok && saved != canonical {
			hint := b.known.Path()
			if hint == "" {
				hint = "known_hosts.json"
			}
			return nil, fmt.Errorf("服务器 %s 记录的指纹是 %s，本次提供的是 %s；如果确认换证，请删除 %s 中对应条目后重试", req.Server, saved, canonical, hint)
		}
	}

	// Otherwise use the remembered pin; if this server has never been seen,
	// fetch its fingerprint and make the user confirm it, like SSH.
	pin := req.Pin
	if pin == "" {
		if saved, ok := b.known.Lookup(req.Server); ok {
			pin = saved
		}
	}
	if pin == "" {
		probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		fp, err := ProbeFingerprint(probeCtx, req.Server)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("读取服务器指纹失败：%w", err)
		}
		return nil, &TrustRequiredError{Server: req.Server, Pin: fp}
	}
	req.Pin = pin

	cfg := Config{
		URL:      req.Server,
		Pin:      req.Pin,
		Nick:     req.Nick,
		Password: req.Password,
	}
	s := &session{
		bridge: b,
		cfg:    cfg,
		status: statusConnecting,
		stop:   make(chan struct{}),
	}
	s.cfg.OnEvent = s.onEvent
	// A closing client is detected by run waiting on cli.Done().

	b.mu.Lock()
	old := b.sess
	b.sess = nil
	b.mu.Unlock()
	if old != nil {
		old.stopSession()
	}

	cli, snap, buffered, err := s.connect(ctx)
	if err != nil {
		if errors.Is(err, ErrPinMismatch) || strings.Contains(err.Error(), "证书指纹不匹配") {
			hint := b.known.Path()
			if hint == "" {
				hint = "known_hosts.json"
			}
			return nil, fmt.Errorf("%w。如果确认服务器换了证书，请先删除 %s 中对应条目，再用 server-info.txt 或高级中的新指纹重新登录", err, hint)
		}
		return nil, err
	}

	b.mu.Lock()
	b.sess = s
	b.prefill = Prefill{URL: req.Server, Pin: req.Pin, Nick: req.Nick}
	b.mu.Unlock()

	if !s.install(cli, snap, buffered) {
		b.mu.Lock()
		if b.sess == s {
			b.sess = nil
		}
		b.mu.Unlock()
		s.stopSession()
		return nil, errors.New("登录已取消")
	}
	if err := b.known.Remember(req.Server, pin); err != nil {
		b.log.Warn("cannot save accepted fingerprint", "server", req.Server, "err", err)
	}
	go s.run()
	b.log.Info("operator logged in", "server", req.Server, "nick", req.Nick)
	return s.snapshotRaw(), nil
}

// Logout disconnects the remote session but keeps the local GUI open.
func (b *Bridge) Logout() {
	b.mu.Lock()
	s := b.sess
	b.sess = nil
	b.mu.Unlock()
	if s != nil {
		s.stopSession()
	}
	b.broadcastStatus(statusOffline, "")
}

func (s *session) connect(ctx context.Context) (*Client, protocol.Snapshot, []protocol.Envelope, error) {
	s.mu.Lock()
	s.buffering = true
	s.buffer = nil
	s.mu.Unlock()

	cli, err := Dial(ctx, s.cfg)
	if err != nil {
		s.mu.Lock()
		s.buffering = false
		s.buffer = nil
		s.mu.Unlock()
		return nil, protocol.Snapshot{}, nil, err
	}
	raw, err := cli.Request(protocol.CmdStateGet, struct{}{}, 15*time.Second)
	if err != nil {
		_ = cli.Close()
		s.mu.Lock()
		s.buffering = false
		s.buffer = nil
		s.mu.Unlock()
		return nil, protocol.Snapshot{}, nil, fmt.Errorf("读取黑板快照失败：%w", err)
	}
	var snap protocol.Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		_ = cli.Close()
		s.mu.Lock()
		s.buffering = false
		s.buffer = nil
		s.mu.Unlock()
		return nil, protocol.Snapshot{}, nil, fmt.Errorf("快照格式错误：%w", err)
	}
	s.mu.Lock()
	buffered := s.buffer
	s.buffer = nil
	s.mu.Unlock()
	return cli, snap, buffered, nil
}

// install publishes a fresh snapshot and then replays events that arrived
// while the snapshot was being fetched.
func (s *session) install(cli *Client, snap protocol.Snapshot, buffered []protocol.Envelope) bool {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		_ = cli.Close()
		return false
	}
	s.cli = cli
	s.snapshot = snap
	s.status = statusOnline
	s.lastErr = ""
	s.buffering = true
	s.mu.Unlock()

	s.bridge.broadcastStatus(statusOnline, "")
	s.bridge.broadcastSnapshot()

	s.mu.Lock()
	more := s.buffer
	s.buffer = nil
	s.buffering = false
	s.mu.Unlock()

	for _, env := range append(buffered, more...) {
		s.mu.Lock()
		applied := s.applyLocked(env)
		s.mu.Unlock()
		if applied {
			s.bridge.publishEnvelope(env)
		}
	}
	return true
}

func (s *session) run() {
	for {
		s.mu.Lock()
		cli := s.cli
		stopped := s.stopped
		s.mu.Unlock()
		if stopped || cli == nil {
			return
		}
		select {
		case <-s.stop:
			return
		case <-cli.Done():
		}

		s.mu.Lock()
		if s.stopped {
			s.mu.Unlock()
			return
		}
		s.cli = nil
		kicked := s.status == statusKicked
		if !kicked {
			s.status = statusReconnecting
		}
		if !kicked || s.lastErr == "" {
			s.lastErr = cli.Err().Error()
		}
		errMsg := s.lastErr
		status := statusReconnecting
		if kicked {
			status = statusKicked
		}
		s.mu.Unlock()
		s.bridge.broadcastStatus(status, errMsg)

		attempt := 0
		for {
			delay := reconnectDelay(attempt)
			select {
			case <-s.stop:
				return
			case <-time.After(delay):
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			cli2, snap, buffered, err := s.connect(ctx)
			cancel()
			if err != nil {
				s.mu.Lock()
				if s.status != statusKicked {
					s.status = statusReconnecting
				}
				s.lastErr = err.Error()
				errMsg = s.lastErr
				status = s.status
				s.mu.Unlock()
				s.bridge.broadcastStatus(status, errMsg)
				attempt++
				if attempt > 5 {
					attempt = 5
				}
				continue
			}
			if !s.install(cli2, snap, buffered) {
				return
			}
			break
		}
	}
}

func reconnectDelay(attempt int) time.Duration {
	delays := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 15 * time.Second, 30 * time.Second}
	if attempt < 0 {
		attempt = 0
	}
	if attempt >= len(delays) {
		return delays[len(delays)-1]
	}
	return delays[attempt]
}

func (s *session) stopSession() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	cli := s.cli
	s.cli = nil
	s.buffer = nil
	close(s.stop)
	s.mu.Unlock()
	if cli != nil {
		_ = cli.Close()
	}
}

func (s *session) statusInfo() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status, s.lastErr
}

func (s *session) snapshotRaw() json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, _ := json.Marshal(s.snapshot)
	return raw
}

func (s *session) command(cmd string, args json.RawMessage, timeout time.Duration) (json.RawMessage, error) {
	s.mu.Lock()
	cli := s.cli
	stopped := s.stopped
	status := s.status
	s.mu.Unlock()
	if stopped || cli == nil {
		return nil, errors.New("连接未就绪，正在重连")
	}
	if status != statusOnline {
		return nil, errors.New("连接未就绪，正在重连")
	}
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	return cli.RequestRaw(cmd, args, timeout)
}

func (s *session) onEvent(env protocol.Envelope) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	if s.buffering || s.status != statusOnline {
		s.buffer = append(s.buffer, env)
		if len(s.buffer) > 512 {
			s.buffer = append([]protocol.Envelope(nil), s.buffer[len(s.buffer)-512:]...)
		}
		s.mu.Unlock()
		return
	}
	applied := s.applyLocked(env)
	s.mu.Unlock()
	if applied {
		s.bridge.publishEnvelope(env)
	}
}

// applyLocked updates the bridge's cached state. It returns false for stale
// events so a late board or message cannot roll the UI back.
func (s *session) applyLocked(env protocol.Envelope) bool {
	switch env.Name {
	case protocol.EventBoard:
		var e protocol.BoardEvent
		if protocol.Decode(env, &e) != nil {
			return false
		}
		if !s.snapshot.Board.ServerTime.IsZero() && e.Board.ServerTime.Before(s.snapshot.Board.ServerTime) {
			return false
		}
		s.snapshot.Board = e.Board
		return true
	case protocol.EventSolverUpsert:
		var e protocol.SolverResult
		if protocol.Decode(env, &e) != nil {
			return false
		}
		sv := e.Solver
		sv.HasWriteup = sv.HasWriteup || strings.TrimSpace(sv.Writeup) != ""
		sv.Writeup = ""
		replaced := false
		for i := range s.snapshot.Solvers {
			if s.snapshot.Solvers[i].ID == sv.ID {
				if !s.snapshot.Solvers[i].UpdatedAt.IsZero() && sv.UpdatedAt.Before(s.snapshot.Solvers[i].UpdatedAt) {
					return false
				}
				s.snapshot.Solvers[i] = sv
				replaced = true
				break
			}
		}
		if !replaced {
			s.snapshot.Solvers = append([]model.Solver{sv}, s.snapshot.Solvers...)
		}
		s.snapshot.Board = e.Board
		return true
	case protocol.EventSolverDelete:
		var e protocol.SolverDeleted
		if protocol.Decode(env, &e) != nil {
			return false
		}
		out := s.snapshot.Solvers[:0]
		for _, sv := range s.snapshot.Solvers {
			if sv.ID != e.ID {
				out = append(out, sv)
			}
		}
		s.snapshot.Solvers = out
		s.snapshot.Board = e.Board
		return true
	case protocol.EventSlotUpsert:
		var e protocol.SlotResult
		if protocol.Decode(env, &e) != nil {
			return false
		}
		replaced := false
		for i := range s.snapshot.Slots {
			if s.snapshot.Slots[i].ID == e.Slot.ID {
				if !s.snapshot.Slots[i].UpdatedAt.IsZero() && e.Slot.UpdatedAt.Before(s.snapshot.Slots[i].UpdatedAt) {
					return false
				}
				s.snapshot.Slots[i] = e.Slot
				replaced = true
				break
			}
		}
		if !replaced {
			s.snapshot.Slots = append([]model.Slot{e.Slot}, s.snapshot.Slots...)
		}
		s.snapshot.Board = e.Board
		return true
	case protocol.EventSettings:
		var e protocol.SettingsResult
		if protocol.Decode(env, &e) != nil {
			return false
		}
		s.snapshot.Settings = e.Settings
		s.snapshot.Board = e.Board
		return true
	case protocol.EventMessage:
		var e protocol.MessageEvent
		if protocol.Decode(env, &e) != nil {
			return false
		}
		if n := len(s.snapshot.Chat); n > 0 && e.Message.ID <= s.snapshot.Chat[n-1].ID {
			return false
		}
		s.snapshot.Chat = append(s.snapshot.Chat, e.Message)
		if len(s.snapshot.Chat) > 200 {
			s.snapshot.Chat = append([]model.Message(nil), s.snapshot.Chat[len(s.snapshot.Chat)-200:]...)
		}
		return true
	case protocol.EventActivity:
		var e protocol.ActivityEvent
		if protocol.Decode(env, &e) != nil {
			return false
		}
		if n := len(s.snapshot.Activity); n > 0 && e.Activity.ID <= s.snapshot.Activity[n-1].ID {
			return false
		}
		s.snapshot.Activity = append(s.snapshot.Activity, e.Activity)
		if len(s.snapshot.Activity) > 200 {
			s.snapshot.Activity = append([]model.Activity(nil), s.snapshot.Activity[len(s.snapshot.Activity)-200:]...)
		}
		return true
	case protocol.EventKicked:
		var e protocol.KickedEvent
		if protocol.Decode(env, &e) != nil {
			return false
		}
		s.lastErr = e.Reason
		s.status = statusKicked
		return true
	}
	return true
}

// ---- local HTTP ----

func (b *Bridge) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func (b *Bridge) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !b.checkToken(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "本地令牌无效，请从客户端打印的地址打开"})
			return
		}
		if r.Method == http.MethodPost && !b.checkOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "Origin 校验失败"})
			return
		}
		next(w, r)
	}
}

func (b *Bridge) checkToken(r *http.Request) bool {
	got := r.Header.Get("X-CTFBB-Token")
	if got == "" && r.URL.Path == "/api/events" {
		got = r.URL.Query().Get("token")
	}
	if len(got) != len(b.token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(b.token)) == 1
}

func (b *Bridge) checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

func (b *Bridge) handlePrefill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"prefill": b.getPrefill(),
		"version": Version,
	})
}

func (b *Bridge) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "登录请求格式错误"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	raw, err := b.Login(ctx, req)
	if err != nil {
		var trust *TrustRequiredError
		if errors.As(err, &trust) {
			writeJSON(w, http.StatusPreconditionRequired, map[string]any{
				"error":         "首次连接，需要确认服务器指纹",
				"trustRequired": true,
				"server":        trust.Server,
				"pin":           trust.Pin,
			})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "snapshot": raw})
}

func (b *Bridge) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	s := b.currentSession()
	prefill := b.getPrefill()
	if s == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"loggedIn": false,
			"status":   statusOffline,
			"prefill":  prefill,
		})
		return
	}
	status, lastErr := s.statusInfo()
	writeJSON(w, http.StatusOK, map[string]any{
		"loggedIn": true,
		"status":   status,
		"error":    lastErr,
		"snapshot": s.snapshotRaw(),
		"prefill":  prefill,
	})
}

type commandRequest struct {
	Cmd  string          `json:"cmd"`
	Args json.RawMessage `json:"args"`
}

func (b *Bridge) handleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req commandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Cmd) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "命令格式错误"})
		return
	}
	s := b.currentSession()
	if s == nil {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "未登录"})
		return
	}
	raw, err := s.command(req.Cmd, req.Args, 20*time.Second)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": raw})
}

func (b *Bridge) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	b.Logout()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": Version})
}

func (b *Bridge) handleQuit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	b.quitOnce.Do(func() { close(b.quit) })
}

func (b *Bridge) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	s := b.currentSession()
	if s == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "未登录"})
		return
	}
	status, _ := s.statusInfo()
	if status != statusOnline {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "连接未就绪，正在重连，稍后再导出"})
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "md"
	}
	filename, content, contentType, err := b.export(s, format)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (b *Bridge) export(s *session, format string) (string, []byte, string, error) {
	if format != "md" && format != "json" {
		return "", nil, "", errors.New("不支持的导出格式")
	}
	solvers := s.exportSolvers()
	full := make([]model.Solver, 0, len(solvers))
	for _, sv := range solvers {
		if sv.HasWriteup {
			raw, err := s.command(protocol.CmdSolverGet, mustJSON(protocol.IDArgs{ID: sv.ID}), 15*time.Second)
			if err != nil {
				sv.Writeup = "_writeup 获取失败：" + err.Error() + "_"
			} else {
				var got protocol.SolverResult
				if json.Unmarshal(raw, &got) == nil {
					sv = got.Solver
				}
			}
		}
		full = append(full, sv)
	}
	sort.SliceStable(full, func(i, j int) bool {
		return full[i].CreatedAt.Before(full[j].CreatedAt)
	})
	settings := s.settingsSnapshot()

	stamp := time.Now().Format("20060102-150405")
	if format == "json" {
		payload, err := json.MarshalIndent(map[string]any{
			"generated_at": time.Now().UTC(),
			"server":       settings.ServerName,
			"settings":     settings,
			"solvers":      full,
		}, "", "  ")
		if err != nil {
			return "", nil, "", err
		}
		return "ctfbb-writeups-" + stamp + ".json", payload, "application/json; charset=utf-8", nil
	}

	var md strings.Builder
	fmt.Fprintf(&md, "# %s — writeups\n\n", settings.ServerName)
	fmt.Fprintf(&md, "- 导出时间：%s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&md, "- 题目总数：%d\n- 已记录战果：%d\n\n", settings.TotalChallenges, len(full))
	for _, sv := range full {
		fmt.Fprintf(&md, "## %s\n\n", sv.Challenge)
		fmt.Fprintf(&md, "- 解题人：%s\n", sv.Nick)
		fmt.Fprintf(&md, "- 记录时间：%s\n", sv.CreatedAt.Local().Format("2006-01-02 15:04:05"))
		if !sv.UpdatedAt.IsZero() {
			fmt.Fprintf(&md, "- 最后更新：%s\n", sv.UpdatedAt.Local().Format("2006-01-02 15:04:05"))
		}
		fmt.Fprintln(&md)
		body := strings.TrimSpace(sv.Writeup)
		if body == "" {
			body = "_还没有写 writeup。_"
		}
		fmt.Fprintln(&md, body)
		fmt.Fprintln(&md)
	}
	return "ctfbb-writeups-" + stamp + ".md", []byte(md.String()), "text/markdown; charset=utf-8", nil
}

func (s *session) exportSolvers() []model.Solver {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Solver, 0, len(s.snapshot.Solvers))
	for _, sv := range s.snapshot.Solvers {
		sv.Writeup = ""
		out = append(out, sv)
	}
	return out
}

func (s *session) settingsSnapshot() model.Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot.Settings
}

func (b *Bridge) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	id, ch := b.subscribe()
	defer b.unsubscribe(id)

	if s := b.currentSession(); s != nil {
		writeSSERaw(w, "snapshot", s.snapshotRaw())
		status, lastErr := s.statusInfo()
		writeSSE(w, "status", statusEvent{Status: status, Error: lastErr})
	} else {
		writeSSE(w, "status", statusEvent{Status: statusOffline})
	}
	flusher.Flush()

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case raw, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", raw)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func (b *Bridge) subscribe() (int, <-chan []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.nextSub
	b.nextSub++
	ch := make(chan []byte, 128)
	b.subs[id] = ch
	return id, ch
}

func (b *Bridge) unsubscribe(id int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.subs, id)
}

func (b *Bridge) publish(raw []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, ch := range b.subs {
		select {
		case ch <- raw:
		default:
			// A stalled browser tab must not backpressure the bridge. Close
			// its stream so EventSource reconnects and fetches a fresh
			// snapshot instead of running with a silent gap.
			delete(b.subs, id)
			close(ch)
		}
	}
}

func (b *Bridge) publishEnvelope(env protocol.Envelope) {
	b.publishRawEvent(env.Name, env.Data)
}

func (b *Bridge) publishRawEvent(name string, data json.RawMessage) {
	raw, err := json.Marshal(localEvent{Name: name, Data: data})
	if err != nil {
		return
	}
	b.publish(raw)
}

func (b *Bridge) broadcastStatus(status, lastErr string) {
	data, _ := json.Marshal(statusEvent{Status: status, Error: lastErr})
	b.publishRawEvent("status", data)
}

func (b *Bridge) broadcastSnapshot() {
	s := b.currentSession()
	if s == nil {
		return
	}
	b.publishRawEvent("snapshot", s.snapshotRaw())
}

func writeSSE(w io.Writer, name string, data any) {
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	writeSSERaw(w, name, raw)
}

func writeSSERaw(w io.Writer, name string, data json.RawMessage) {
	raw, err := json.Marshal(localEvent{Name: name, Data: data})
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "data: %s\n\n", raw)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func mustJSON(v any) json.RawMessage {
	raw, _ := json.Marshal(v)
	return raw
}

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func loopbackHost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
