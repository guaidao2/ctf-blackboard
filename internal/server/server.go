package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/ctf-blackboard/internal/model"
	"github.com/guaidao2/ctf-blackboard/internal/store"
)

// Server owns the TLS listener, the HTTP/WebSocket endpoint and the in-memory
// hub. Start returns immediately; call Close for a graceful shutdown.
type Server struct {
	cfg      Config
	log      *slog.Logger
	store    *store.Store
	hub      *Hub
	cert     tls.Certificate
	certFile string
	keyFile  string
	pin      string
	tls      *tls.Config

	mu       sync.Mutex
	listener net.Listener
	httpSrv  *http.Server
	addr     string
	url      string
	closed   bool
	created  bool
}

// Info is what the CLI prints and writes to server-info.txt.
type Info struct {
	URL      string
	Pin      string
	Listen   string
	DataFile string
	CertFile string
	KeyFile  string
	Created  bool
	Settings model.Settings
}

// New loads the state, prepares the certificate and builds the hub. It does
// not bind a port yet.
func New(cfg Config) (*Server, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}

	initial := model.Settings{
		ServerName:      cfg.ServerName,
		Motd:            cfg.Motd,
		SlotLimit:       cfg.SlotLimit,
		TotalChallenges: cfg.TotalChallenges,
	}
	bd, st, created, err := store.Open(cfg.DataDir, initial)
	if err != nil {
		return nil, err
	}

	cert, pin, certFile, keyFile, err := loadOrCreateCertificate(cfg.DataDir, cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:      cfg,
		log:      cfg.Logger,
		store:    bd,
		cert:     cert,
		certFile: certFile,
		keyFile:  keyFile,
		pin:      pin,
		created:  created,
		tls: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"http/1.1"},
		},
	}
	s.hub = newHub(cfg, st, s.store)

	if bd.Recovered() {
		s.log.Warn("state was corrupt; restored the previous backup", "file", bd.Path())
	}
	if created {
		s.log.Info("created new blackboard state", "file", bd.Path())
	} else {
		s.log.Info("loaded blackboard state", "file", bd.Path())
	}
	return s, nil
}

// Start binds the listener and serves in the background. The returned Info
// contains the reachable URL and certificate pin to hand to teammates.
func (s *Server) Start() (Info, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Info{}, errors.New("server is closed")
	}
	if s.listener != nil {
		return s.infoLocked(), errors.New("server already started")
	}

	base, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return Info{}, fmt.Errorf("listen on %s: %w", s.cfg.Listen, err)
	}
	s.listener = base
	s.addr = base.Addr().String()
	s.url = s.buildURLLocked()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.hub.handleWebSocket)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/", s.handleRoot)
	s.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}

	tlsListener := tls.NewListener(base, s.tls)
	go func() {
		err := s.httpSrv.Serve(tlsListener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("http server stopped", "err", err)
		}
	}()

	info := s.infoLocked()
	if err := s.writeInfoLocked(info); err != nil {
		s.log.Warn("could not write server-info.txt", "err", err)
	}
	s.log.Info("server listening",
		"listen", info.Listen,
		"url", info.URL,
		"pin", info.Pin,
		"slots", info.Settings.SlotLimit,
		"total_challenges", info.Settings.TotalChallenges,
	)
	return info, nil
}

// Info returns the startup information. It is valid after Start.
func (s *Server) Info() Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.infoLocked()
}

func (s *Server) infoLocked() Info {
	return Info{
		URL:      s.url,
		Pin:      s.pin,
		Listen:   s.addr,
		DataFile: s.store.Path(),
		CertFile: s.certFile,
		KeyFile:  s.keyFile,
		Created:  s.created,
		Settings: s.hub.settings(),
	}
}

func (s *Server) buildURLLocked() string {
	if strings.TrimSpace(s.cfg.PublicURL) != "" {
		return strings.TrimSpace(s.cfg.PublicURL)
	}
	host, port, err := net.SplitHostPort(s.addr)
	if err != nil {
		return "wss://" + s.addr + "/ws"
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = bestHost()
	}
	return "wss://" + net.JoinHostPort(host, port) + "/ws"
}

func (s *Server) writeInfoLocked(info Info) error {
	content := strings.Join([]string{
		"# CTF Blackboard server info — hand this file to the client",
		"name=" + info.Settings.ServerName,
		"url=" + info.URL,
		"pin=" + info.Pin,
		"",
	}, "\n")
	path := filepath.Join(s.cfg.DataDir, "server-info.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	s.log.Info("wrote server info", "file", path)
	return nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("CTF Blackboard server. Connect with ctfbb-client.\n"))
}

// Close stops accepting connections, disconnects operators, persists state and
// shuts down the HTTP server.
func (s *Server) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	httpSrv := s.httpSrv
	s.mu.Unlock()

	s.hub.shutdown()

	if httpSrv != nil {
		if err := httpSrv.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown http server: %w", err)
		}
	}
	return nil
}
