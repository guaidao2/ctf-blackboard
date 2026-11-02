package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/guaidao2/ctf-blackboard/internal/protocol"
	"github.com/guaidao2/ctf-blackboard/internal/secure"
)

const testPassword = "correct-horse-battery-staple"

func testConfig(dir string) Config {
	return Config{
		Listen:          "127.0.0.1:0",
		DataDir:         dir,
		Password:        testPassword,
		ServerName:      "test board",
		Motd:            "test motd",
		SlotLimit:       1,
		TotalChallenges: 2,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func startTestServer(t *testing.T, cfg Config) (*Server, Info) {
	t.Helper()
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	info, err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Close(ctx)
	})
	return srv, info
}

type testPeer struct {
	t         *testing.T
	conn      *websocket.Conn
	send      *secure.FrameCipher
	recv      *secure.FrameCipher
	writeMu   sync.Mutex
	events    chan protocol.Envelope
	responses chan protocol.Envelope
	done      chan struct{}
	closeOnce sync.Once
	nextID    atomic.Uint64
	snapshot  protocol.Snapshot
}

func dialPeer(t *testing.T, info Info, nick, password string) (*testPeer, error) {
	t.Helper()
	wantPin, err := secure.NormalizeFingerprint(info.Pin)
	if err != nil {
		t.Fatalf("normalize pin: %v", err)
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no certificate")
			}
			got, err := secure.NormalizeFingerprint(secure.Fingerprint(rawCerts[0]))
			if err != nil {
				return err
			}
			if got != wantPin {
				return fmt.Errorf("certificate pin mismatch")
			}
			return nil
		},
	}
	dialer := websocket.Dialer{
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 5 * time.Second,
	}
	conn, resp, err := dialer.Dial(info.URL, nil)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("dial: %w (http %s)", err, resp.Status)
		}
		return nil, fmt.Errorf("dial: %w", err)
	}

	closeConn := func() { _ = conn.Close() }
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))

	clientNonce := make([]byte, 32)
	_, _ = rand.Read(clientNonce)
	helloEnv, _ := protocol.NewDataEnvelope(protocol.TypeHello, protocol.Hello{
		Version: protocol.Version,
		Nick:    nick,
		Nonce:   protocol.B64(clientNonce),
		Client:  "ctfbb-test",
	})
	if err := writeText(conn, helloEnv); err != nil {
		closeConn()
		return nil, err
	}
	chEnv, err := readText(conn)
	if err != nil {
		closeConn()
		return nil, fmt.Errorf("read challenge: %w", err)
	}
	if chEnv.Type == protocol.TypeError {
		closeConn()
		return nil, errors.New(chEnv.Error)
	}
	var challenge protocol.Challenge
	if err := protocol.Decode(chEnv, &challenge); err != nil {
		closeConn()
		return nil, err
	}
	if challenge.Iterations < secure.MinIterations {
		closeConn()
		return nil, fmt.Errorf("server requested weak PBKDF2 iterations")
	}
	salt, err := protocol.UnB64(challenge.Salt, 16)
	if err != nil {
		closeConn()
		return nil, err
	}
	serverNonce, err := protocol.UnB64(challenge.Nonce, 32)
	if err != nil {
		closeConn()
		return nil, err
	}
	master, err := secure.DeriveLoginKey(password, salt, challenge.Iterations)
	if err != nil {
		closeConn()
		return nil, err
	}
	authEnv, _ := protocol.NewDataEnvelope(protocol.TypeAuth, protocol.Auth{
		Proof: protocol.B64(secure.ClientProof(master, nick, clientNonce, serverNonce)),
	})
	if err := writeText(conn, authEnv); err != nil {
		closeConn()
		return nil, err
	}
	welcomeEnv, err := readText(conn)
	if err != nil {
		closeConn()
		return nil, fmt.Errorf("read welcome: %w", err)
	}
	if welcomeEnv.Type == protocol.TypeError {
		closeConn()
		return nil, errors.New(welcomeEnv.Error)
	}
	var welcome protocol.Welcome
	if err := protocol.Decode(welcomeEnv, &welcome); err != nil {
		closeConn()
		return nil, err
	}
	wantProof := secure.ServerProof(master, nick, clientNonce, serverNonce)
	gotProof, err := protocol.UnB64(welcome.Proof, 32)
	if err != nil || !secure.VerifyMAC(wantProof, gotProof) {
		closeConn()
		return nil, errors.New("server proof did not verify")
	}

	c2sKey, s2cKey, err := secure.SessionKeys(master, nick, clientNonce, serverNonce)
	if err != nil {
		closeConn()
		return nil, err
	}
	sendCipher, err := secure.NewFrameCipher(c2sKey, secure.DirectionClientToServer)
	if err != nil {
		closeConn()
		return nil, err
	}
	recvCipher, err := secure.NewFrameCipher(s2cKey, secure.DirectionServerToClient)
	if err != nil {
		closeConn()
		return nil, err
	}

	p := &testPeer{
		t:         t,
		conn:      conn,
		send:      sendCipher,
		recv:      recvCipher,
		events:    make(chan protocol.Envelope, 128),
		responses: make(chan protocol.Envelope, 128),
		done:      make(chan struct{}),
	}
	_ = conn.SetReadDeadline(time.Time{})
	go p.readLoop()
	if snapEnv, err := p.waitEvent(protocol.EventSnapshot, 5*time.Second); err != nil {
		p.close()
		return nil, err
	} else if err := protocol.Decode(snapEnv, &p.snapshot); err != nil {
		p.close()
		return nil, err
	}
	return p, nil
}

func (p *testPeer) readLoop() {
	defer close(p.done)
	for {
		mt, data, err := p.conn.ReadMessage()
		if err != nil {
			return
		}
		if mt != websocket.BinaryMessage {
			return
		}
		plain, err := p.recv.Open(data)
		if err != nil {
			return
		}
		var env protocol.Envelope
		if err := json.Unmarshal(plain, &env); err != nil {
			return
		}
		switch env.Type {
		case protocol.TypeEvent:
			select {
			case p.events <- env:
			case <-p.done:
				return
			}
		case protocol.TypeResponse:
			select {
			case p.responses <- env:
			case <-p.done:
				return
			}
		}
	}
}

func (p *testPeer) close() {
	p.closeOnce.Do(func() {
		_ = p.conn.Close()
	})
}

func (p *testPeer) request(cmd string, args any) protocol.Envelope {
	p.t.Helper()
	id := fmt.Sprintf("req-%d", p.nextID.Add(1))
	argRaw, err := json.Marshal(args)
	if err != nil {
		p.t.Fatalf("marshal args: %v", err)
	}
	req := protocol.Request{Cmd: cmd, Args: argRaw}
	data, err := json.Marshal(req)
	if err != nil {
		p.t.Fatalf("marshal request: %v", err)
	}
	env := protocol.Envelope{Type: protocol.TypeRequest, ID: id, Data: data}
	raw, err := json.Marshal(env)
	if err != nil {
		p.t.Fatalf("marshal envelope: %v", err)
	}
	frame, err := p.send.Seal(raw)
	if err != nil {
		p.t.Fatalf("seal: %v", err)
	}
	p.writeMu.Lock()
	_ = p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err = p.conn.WriteMessage(websocket.BinaryMessage, frame)
	p.writeMu.Unlock()
	if err != nil {
		p.t.Fatalf("write request: %v", err)
	}

	timeout := time.After(8 * time.Second)
	for {
		select {
		case resp := <-p.responses:
			if resp.ReplyTo == id {
				return resp
			}
		case <-p.done:
			p.t.Fatalf("connection closed while waiting for %s", cmd)
		case <-timeout:
			p.t.Fatalf("timeout waiting for %s", cmd)
		}
	}
}

func (p *testPeer) mustOK(cmd string, args any) protocol.Envelope {
	p.t.Helper()
	resp := p.request(cmd, args)
	if !resp.OK {
		p.t.Fatalf("%s failed: %s", cmd, resp.Error)
	}
	return resp
}

func (p *testPeer) waitEvent(name string, timeout time.Duration) (protocol.Envelope, error) {
	deadline := time.After(timeout)
	for {
		select {
		case env := <-p.events:
			if env.Name == name {
				return env, nil
			}
		case <-p.done:
			return protocol.Envelope{}, errors.New("connection closed")
		case <-deadline:
			return protocol.Envelope{}, fmt.Errorf("timeout waiting for event %s", name)
		}
	}
}

func (p *testPeer) waitBoardAtLeast(n int, timeout time.Duration) (protocol.BoardEvent, error) {
	deadline := time.After(timeout)
	for {
		select {
		case env := <-p.events:
			if env.Name != protocol.EventBoard {
				continue
			}
			var be protocol.BoardEvent
			if err := protocol.Decode(env, &be); err != nil {
				return protocol.BoardEvent{}, err
			}
			if len(be.Board.Operators) >= n {
				return be, nil
			}
		case <-p.done:
			return protocol.BoardEvent{}, errors.New("connection closed")
		case <-deadline:
			return protocol.BoardEvent{}, fmt.Errorf("timeout waiting for board with %d operators", n)
		}
	}
}

func decodeEvent[T any](t *testing.T, env protocol.Envelope) T {
	t.Helper()
	var v T
	if err := protocol.Decode(env, &v); err != nil {
		t.Fatalf("decode event %s: %v", env.Name, err)
	}
	return v
}

func writeText(conn *websocket.Conn, env protocol.Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return conn.WriteMessage(websocket.TextMessage, data)
}

func readText(conn *websocket.Conn) (protocol.Envelope, error) {
	mt, data, err := conn.ReadMessage()
	if err != nil {
		return protocol.Envelope{}, err
	}
	if mt != websocket.TextMessage {
		return protocol.Envelope{}, fmt.Errorf("expected text frame, got %d", mt)
	}
	var env protocol.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return protocol.Envelope{}, err
	}
	return env, nil
}

func TestBlackboardEndToEnd(t *testing.T) {
	dir := t.TempDir()
	srv, info := startTestServer(t, testConfig(dir))

	alice, err := dialPeer(t, info, "alice", testPassword)
	if err != nil {
		t.Fatalf("alice login: %v", err)
	}
	defer alice.close()

	snap := alice.snapshot
	if snap.You != "alice" || snap.Board.TotalChallenges != 2 || snap.Board.SlotLimit != 1 {
		t.Fatalf("unexpected initial snapshot: you=%s board=%+v", snap.You, snap.Board)
	}

	bob, err := dialPeer(t, info, "bob", testPassword)
	if err != nil {
		t.Fatalf("bob login: %v", err)
	}
	defer bob.close()
	boardEv, err := alice.waitBoardAtLeast(2, 2*time.Second)
	if err != nil {
		t.Fatalf("alice did not see bob's presence: %v", err)
	}
	if len(boardEv.Board.Operators) != 2 {
		t.Fatalf("operators = %d, want 2", len(boardEv.Board.Operators))
	}

	// Chat.
	alice.mustOK(protocol.CmdChatSend, protocol.ChatSendArgs{Text: "hello team"})
	msgEnv, err := bob.waitEvent(protocol.EventMessage, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	msg := decodeEvent[protocol.MessageEvent](t, msgEnv)
	if msg.Message.Nick != "alice" || msg.Message.Text != "hello team" {
		t.Fatalf("unexpected chat message: %+v", msg.Message)
	}

	// Solver: only the final submitter matters, one entry per challenge.
	resp := alice.mustOK(protocol.CmdSolverAdd, protocol.SolverAddArgs{
		Challenge: "ezsql", Nick: "alice", Writeup: "# union\nselect flag",
	})
	var added protocol.SolverResult
	if err := protocol.Decode(resp, &added); err != nil {
		t.Fatal(err)
	}
	if added.Solver.ID == "" || added.Board.SolvedChallenges != 1 {
		t.Fatalf("unexpected solver result: %+v", added)
	}
	upsertEnv, err := bob.waitEvent(protocol.EventSolverUpsert, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	upsert := decodeEvent[protocol.SolverResult](t, upsertEnv)
	if upsert.Solver.Challenge != "ezsql" || !upsert.Solver.HasWriteup {
		t.Fatalf("unexpected upsert event: %+v", upsert.Solver)
	}
	if upsert.Solver.Writeup != "" {
		t.Fatalf("upsert event leaked writeup content: %q", upsert.Solver.Writeup)
	}

	dup := bob.request(protocol.CmdSolverAdd, protocol.SolverAddArgs{Challenge: "EZSQL", Nick: "bob"})
	if dup.OK || !strings.Contains(dup.Error, "已有战果") {
		t.Fatalf("duplicate solver accepted: ok=%v err=%q", dup.OK, dup.Error)
	}

	getResp := bob.mustOK(protocol.CmdSolverGet, protocol.IDArgs{ID: added.Solver.ID})
	var got protocol.SolverResult
	if err := protocol.Decode(getResp, &got); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Solver.Writeup, "union") {
		t.Fatalf("writeup not fetched: %q", got.Solver.Writeup)
	}

	// Slot quota: one slot, second open must be refused with the occupant list.
	slotResp := alice.mustOK(protocol.CmdSlotOpen, protocol.SlotOpenArgs{
		Challenge: "ezsql", URL: "http://127.0.0.1:3000",
	})
	var opened protocol.SlotResult
	if err := protocol.Decode(slotResp, &opened); err != nil {
		t.Fatal(err)
	}
	if opened.Board.ActiveSlots != 1 {
		t.Fatalf("active slots = %d", opened.Board.ActiveSlots)
	}
	full := bob.request(protocol.CmdSlotOpen, protocol.SlotOpenArgs{Challenge: "pwn"})
	if full.OK || !strings.Contains(full.Error, "容器位已满") || !strings.Contains(full.Error, "ezsql") {
		t.Fatalf("slot quota not enforced: ok=%v err=%q", full.OK, full.Error)
	}

	alice.mustOK(protocol.CmdSlotRelease, protocol.IDArgs{ID: opened.Slot.ID})
	bob.mustOK(protocol.CmdSlotOpen, protocol.SlotOpenArgs{Challenge: "pwn"})

	// Dynamic settings: total challenges and slot limit are editable anytime.
	three, two := 3, 2
	settingsResp := bob.mustOK(protocol.CmdSettingsUpdate, protocol.SettingsUpdateArgs{
		TotalChallenges: &three,
		SlotLimit:       &two,
	})
	var settings protocol.SettingsResult
	if err := protocol.Decode(settingsResp, &settings); err != nil {
		t.Fatal(err)
	}
	if settings.Settings.TotalChallenges != 3 || settings.Settings.SlotLimit != 2 {
		t.Fatalf("settings not updated: %+v", settings.Settings)
	}

	zero := 0
	lower := bob.request(protocol.CmdSettingsUpdate, protocol.SettingsUpdateArgs{TotalChallenges: &zero})
	if lower.OK || !strings.Contains(lower.Error, "不能小于") {
		t.Fatalf("total below solved accepted: ok=%v err=%q", lower.OK, lower.Error)
	}

	// Raising and lowering the slot limit is allowed at runtime.
	one := 1
	lowerResp := bob.mustOK(protocol.CmdSettingsUpdate, protocol.SettingsUpdateArgs{SlotLimit: &one})
	var lowerSettings protocol.SettingsResult
	if err := protocol.Decode(lowerResp, &lowerSettings); err != nil {
		t.Fatal(err)
	}
	if lowerSettings.Settings.SlotLimit != 1 {
		t.Fatalf("lowered slot limit = %d, want 1", lowerSettings.Settings.SlotLimit)
	}

	// Persistence across a server restart.
	alice.close()
	bob.close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := srv.Close(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()

	_, info2 := startTestServer(t, testConfig(dir))
	alice2, err := dialPeer(t, info2, "alice", testPassword)
	if err != nil {
		t.Fatalf("relogin after restart: %v", err)
	}
	defer alice2.close()
	snap2 := alice2.snapshot
	if len(snap2.Solvers) != 1 || snap2.Solvers[0].Challenge != "ezsql" || !snap2.Solvers[0].HasWriteup {
		t.Fatalf("solver lost after restart: %+v", snap2.Solvers)
	}
	if snap2.Settings.TotalChallenges != 3 || snap2.Settings.SlotLimit != 1 {
		t.Fatalf("settings lost after restart: %+v", snap2.Settings)
	}
	active := 0
	for _, sl := range snap2.Slots {
		if sl.Active() {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("active slot lost after restart: %d", active)
	}
}

func TestWrongPasswordAndKick(t *testing.T) {
	dir := t.TempDir()
	_, info := startTestServer(t, testConfig(dir))

	if _, err := dialPeer(t, info, "alice", "wrong-password"); err == nil || !strings.Contains(err.Error(), "密码错误") {
		t.Fatalf("wrong password was not rejected: %v", err)
	}

	alice, err := dialPeer(t, info, "alice", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer alice.close()
	bob, err := dialPeer(t, info, "bob", testPassword)
	if err != nil {
		t.Fatal(err)
	}

	alice.mustOK(protocol.CmdKick, protocol.KickArgs{Nick: "bob"})
	kickEnv, err := bob.waitEvent(protocol.EventKicked, 2*time.Second)
	if err != nil {
		t.Fatalf("bob did not receive kick event: %v", err)
	}
	kick := decodeEvent[protocol.KickedEvent](t, kickEnv)
	if kick.By != "alice" || !strings.Contains(kick.Reason, "踢出") {
		t.Fatalf("unexpected kick event: %+v", kick)
	}

	// The kicked nickname is in cooldown and cannot immediately reconnect.
	if _, err := dialPeer(t, info, "bob", testPassword); err == nil || !strings.Contains(err.Error(), "刚被踢出") {
		t.Fatalf("kicked nickname reconnected: %v", err)
	}

	// Alice can still refresh her view and sees only herself online.
	resp := alice.mustOK(protocol.CmdStateGet, struct{}{})
	var snap protocol.Snapshot
	if err := protocol.Decode(resp, &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.Board.Operators) != 1 || snap.Board.Operators[0].Nick != "alice" {
		t.Fatalf("unexpected operators after kick: %+v", snap.Board.Operators)
	}

	// The HTTP health endpoint is served over TLS.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: infoTLS(t, info)}}
	healthURL := strings.Replace(strings.TrimSuffix(info.URL, "/ws"), "wss://", "https://", 1) + "/healthz"
	respHTTP, err := client.Get(healthURL)
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	defer respHTTP.Body.Close()
	if respHTTP.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", respHTTP.StatusCode)
	}
}

func infoTLS(t *testing.T, info Info) *tls.Config {
	t.Helper()
	wantPin, err := secure.NormalizeFingerprint(info.Pin)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no certificate")
			}
			got, err := secure.NormalizeFingerprint(secure.Fingerprint(rawCerts[0]))
			if err != nil {
				return err
			}
			if got != wantPin {
				return errors.New("pin mismatch")
			}
			return nil
		},
	}
}

func TestSettingsUpdateIsAtomic(t *testing.T) {
	dir := t.TempDir()
	_, info := startTestServer(t, testConfig(dir))
	alice, err := dialPeer(t, info, "alice", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer alice.close()

	five, bad := 5, -1
	resp := alice.request(protocol.CmdSettingsUpdate, protocol.SettingsUpdateArgs{
		TotalChallenges: &five,
		SlotLimit:       &bad,
	})
	if resp.OK || !strings.Contains(resp.Error, "容器位上限") {
		t.Fatalf("invalid settings were accepted: ok=%v err=%q", resp.OK, resp.Error)
	}

	stateResp := alice.mustOK(protocol.CmdStateGet, struct{}{})
	var snap protocol.Snapshot
	if err := protocol.Decode(stateResp, &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Settings.TotalChallenges != 2 || snap.Settings.SlotLimit != 1 {
		t.Fatalf("partial settings update leaked: %+v", snap.Settings)
	}
}
