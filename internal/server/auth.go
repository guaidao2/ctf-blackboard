package server

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/guaidao2/ctf-blackboard/internal/protocol"
	"github.com/guaidao2/ctf-blackboard/internal/secure"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  8192,
	WriteBufferSize: 8192,
	// The operator client is a Go program and sends no Origin header. A
	// browser has no business opening the raw protocol port directly.
	CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" },
}

func (h *Hub) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Warn("websocket upgrade failed", "remote", r.RemoteAddr, "err", err)
		return
	}
	if err := h.login(conn, r); err != nil {
		_ = writeHandshake(conn, protocol.Envelope{Type: protocol.TypeError, Error: err.Error()})
		_ = conn.Close()
		h.log.Info("login rejected", "remote", r.RemoteAddr, "reason", err)
	}
}

func (h *Hub) login(conn *websocket.Conn, r *http.Request) error {
	ip := remoteIP(r)
	conn.SetReadLimit(16 << 10)
	conn.SetReadDeadline(time.Now().Add(h.cfg.HandshakeTimeout))

	env, err := readHandshake(conn, h.cfg.HandshakeTimeout)
	if err != nil {
		return errors.New("握手失败")
	}
	if env.Type != protocol.TypeHello {
		return errors.New("协议错误：缺少 hello")
	}
	var hello protocol.Hello
	if err := protocol.Decode(env, &hello); err != nil {
		return errors.New("hello 格式错误")
	}
	if hello.Version != protocol.Version {
		return fmt.Errorf("客户端协议版本 %d 与服务端 %d 不匹配", hello.Version, protocol.Version)
	}
	nick, err := normalizeNick(hello.Nick)
	if err != nil {
		return err
	}
	clientNonce, err := protocol.UnB64(hello.Nonce, 32)
	if err != nil {
		return errors.New("客户端随机数无效")
	}

	if ok, wait := h.limiter.begin(ip); !ok {
		return fmt.Errorf("登录尝试过多，请 %d 秒后再试", int(wait.Seconds())+1)
	}
	settled := false
	defer func() {
		if !settled {
			h.limiter.cancel(ip)
		}
	}()

	// Do not reveal whether a nickname is online or kicked before the HMAC
	// proof has been verified. Only the server-closed state is checked here.
	h.mu.Lock()
	closed := h.closed
	serverName := h.state.Settings.ServerName
	h.mu.Unlock()
	if closed {
		return errors.New("服务端正在关闭")
	}

	salt := make([]byte, 16)
	serverNonce := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return errors.New("服务端随机数生成失败")
	}
	if _, err := rand.Read(serverNonce); err != nil {
		return errors.New("服务端随机数生成失败")
	}

	challenge := protocol.Challenge{
		Version:    protocol.Version,
		Server:     serverName,
		Salt:       protocol.B64(salt),
		Nonce:      protocol.B64(serverNonce),
		Iterations: secure.DefaultIterations,
	}
	chEnv, err := protocol.NewDataEnvelope(protocol.TypeChallenge, challenge)
	if err != nil {
		return errors.New("内部错误")
	}
	if err := writeHandshake(conn, chEnv); err != nil {
		return errors.New("握手写入失败")
	}

	authEnv, err := readHandshake(conn, h.cfg.HandshakeTimeout)
	if err != nil {
		return errors.New("握手超时")
	}
	if authEnv.Type != protocol.TypeAuth {
		return errors.New("协议错误：缺少 auth")
	}
	var auth protocol.Auth
	if err := protocol.Decode(authEnv, &auth); err != nil {
		return errors.New("auth 格式错误")
	}
	proof, err := protocol.UnB64(auth.Proof, 32)
	if err != nil {
		return errors.New("认证证明无效")
	}

	master, err := secure.DeriveLoginKey(h.cfg.Password, salt, secure.DefaultIterations)
	if err != nil {
		h.log.Error("password derivation failed", "err", err)
		return errors.New("服务端认证配置错误")
	}
	expected := secure.ClientProof(master, nick, clientNonce, serverNonce)
	if !secure.VerifyMAC(expected, proof) {
		h.limiter.fail(ip)
		settled = true
		time.Sleep(350 * time.Millisecond)
		return errors.New("密码错误")
	}
	h.limiter.success(ip)
	settled = true

	if rem := h.kickRemaining(nick); rem > 0 {
		return fmt.Errorf("该昵称刚被踢出，请 %d 秒后再试", int(rem.Seconds())+1)
	}
	h.mu.Lock()
	taken := h.nickTakenLocked(nick)
	closed = h.closed
	h.mu.Unlock()
	if closed {
		return errors.New("服务端正在关闭")
	}
	if taken {
		return errors.New("昵称已被在线操作员占用，请换一个")
	}

	c2sKey, s2cKey, err := secure.SessionKeys(master, nick, clientNonce, serverNonce)
	if err != nil {
		h.log.Error("session key derivation failed", "err", err)
		return errors.New("内部错误")
	}
	recvCipher, err := secure.NewFrameCipher(c2sKey, secure.DirectionClientToServer)
	if err != nil {
		return errors.New("内部错误")
	}
	sendCipher, err := secure.NewFrameCipher(s2cKey, secure.DirectionServerToClient)
	if err != nil {
		return errors.New("内部错误")
	}

	welcome := protocol.Welcome{
		Version: protocol.Version,
		Server:  serverName,
		You:     nick,
		Proof:   protocol.B64(secure.ServerProof(master, nick, clientNonce, serverNonce)),
	}
	welcomeEnv, err := protocol.NewDataEnvelope(protocol.TypeWelcome, welcome)
	if err != nil {
		return errors.New("内部错误")
	}
	if err := writeHandshake(conn, welcomeEnv); err != nil {
		return errors.New("握手写入失败")
	}

	// Re-check after the password work, then register. The welcome is already
	// on the wire, so a race is resolved by the server closing the connection.
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return errors.New("服务端正在关闭")
	}
	if h.nickTakenLocked(nick) {
		h.mu.Unlock()
		return errors.New("昵称已被在线操作员占用，请换一个")
	}
	c := newClient(h, conn, nick, ip, sendCipher, recvCipher)
	h.clients[c] = struct{}{}
	h.byNick[lowerNick(nick)] = c
	snapshot := h.snapshotLocked(nick)
	snapEnv, snapErr := protocol.NewEvent(protocol.EventSnapshot, snapshot)
	var snapRaw []byte
	if snapErr == nil {
		snapRaw, snapErr = json.Marshal(snapEnv)
	}
	if snapErr == nil {
		// Queue the snapshot while still holding the lock, so no other
		// broadcast can slip in ahead of it.
		c.enqueue(snapRaw)
	}
	h.mu.Unlock()

	conn.SetReadLimit(int64(secure.MaxFrameSize + secure.FrameOverhead + 4096))
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	c.start()

	h.mu.Lock()
	h.broadcastBoardLocked()
	h.mu.Unlock()

	c.log.Info("operator connected")
	return nil
}

func readHandshake(conn *websocket.Conn, timeout time.Duration) (protocol.Envelope, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	mt, data, err := conn.ReadMessage()
	if err != nil {
		return protocol.Envelope{}, err
	}
	if mt != websocket.TextMessage {
		return protocol.Envelope{}, errors.New("handshake must use text frames")
	}
	if len(data) > 16<<10 {
		return protocol.Envelope{}, errors.New("handshake frame too large")
	}
	var env protocol.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return protocol.Envelope{}, err
	}
	return env, nil
}

func writeHandshake(conn *websocket.Conn, env protocol.Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return conn.WriteMessage(websocket.TextMessage, data)
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

type loginBucket struct {
	failures     int
	inFlight     int
	windowStart  time.Time
	blockedUntil time.Time
}

type loginLimiter struct {
	mu            sync.Mutex
	maxFailures   int
	maxConcurrent int
	window        time.Duration
	block         time.Duration
	buckets       map[string]*loginBucket
	lastSweep     time.Time
}

func newLoginLimiter(maxFailures, maxConcurrent int, window, block time.Duration) *loginLimiter {
	return &loginLimiter{
		maxFailures:   maxFailures,
		maxConcurrent: maxConcurrent,
		window:        window,
		block:         block,
		buckets:       map[string]*loginBucket{},
	}
}

// begin reserves one attempt before the expensive PBKDF2/HMAC work. Failure
// budget and in-flight concurrency are separate: a team behind one NAT can
// have several valid logins at once, while wrong passwords are still capped.
func (l *loginLimiter) begin(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweepLocked(now)

	b := l.buckets[ip]
	if b == nil {
		b = &loginBucket{windowStart: now}
		l.buckets[ip] = b
	}
	if now.Before(b.blockedUntil) {
		return false, time.Until(b.blockedUntil)
	}
	if now.Sub(b.windowStart) > l.window {
		b.failures = 0
		b.windowStart = now
	}
	if b.inFlight >= l.maxConcurrent {
		return false, time.Second
	}
	b.inFlight++
	return true, 0
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.buckets[ip]
	if b == nil {
		b = &loginBucket{windowStart: now}
		l.buckets[ip] = b
	}
	if b.inFlight > 0 {
		b.inFlight--
	}
	if now.Sub(b.windowStart) > l.window {
		b.failures = 0
		b.windowStart = now
	}
	b.failures++
	if b.failures >= l.maxFailures {
		b.failures = 0
		b.windowStart = now
		b.blockedUntil = now.Add(l.block)
	}
}

func (l *loginLimiter) success(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[ip]
	if b == nil {
		return
	}
	if b.inFlight > 0 {
		b.inFlight--
	}
	b.failures = 0
	if b.inFlight == 0 && !time.Now().Before(b.blockedUntil) {
		delete(l.buckets, ip)
	}
}

// cancel releases a reservation that never reached the proof check.
func (l *loginLimiter) cancel(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[ip]
	if b == nil {
		return
	}
	if b.inFlight > 0 {
		b.inFlight--
	}
	if b.inFlight == 0 && b.failures == 0 && !time.Now().Before(b.blockedUntil) {
		delete(l.buckets, ip)
	}
}

func (l *loginLimiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < 10*time.Minute {
		return
	}
	l.lastSweep = now
	for ip, b := range l.buckets {
		if b.inFlight == 0 && now.After(b.blockedUntil) && now.Sub(b.windowStart) > l.window {
			delete(l.buckets, ip)
		}
	}
}
