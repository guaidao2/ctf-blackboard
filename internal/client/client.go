// Package client implements the remote side of the blackboard protocol and
// the local bridge that serves the browser GUI.
package client

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/guaidao2/ctf-blackboard/internal/protocol"
	"github.com/guaidao2/ctf-blackboard/internal/secure"
)

const (
	handshakeWait = 15 * time.Second
	readWait      = 90 * time.Second
	writeWait     = 10 * time.Second
)

// ErrPinMismatch marks a certificate whose fingerprint differs from the one
// the user accepted. Callers must fail closed and never auto-update it.
var ErrPinMismatch = errors.New("证书指纹不匹配")

// Config describes one remote login. The password is kept only in memory.
type Config struct {
	URL      string
	Pin      string
	Nick     string
	Password string

	OnEvent func(protocol.Envelope)
}

// Client is an authenticated, encrypted connection to the blackboard.
type Client struct {
	conn   *websocket.Conn
	send   *secure.FrameCipher
	recv   *secure.FrameCipher
	events func(protocol.Envelope)

	assembler protocol.Assembler

	writeMu sync.Mutex
	pendMu  sync.Mutex
	pending map[string]chan protocol.Envelope
	nextID  atomic.Uint64

	closeOnce sync.Once
	done      chan struct{}
	errMu     sync.Mutex
	err       error
}

// Dial performs the TLS handshake, proves the shared password and starts the
// encrypted session. The returned client is ready for Request.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil || u.Scheme == "" {
		return nil, fmt.Errorf("服务器地址无效，示例：wss://192.168.1.10:8443/ws")
	}
	if u.Scheme != "wss" {
		return nil, fmt.Errorf("只接受 wss://（通信必须加密），收到 %s", u.Scheme)
	}
	pin, err := secure.NormalizeFingerprint(cfg.Pin)
	if err != nil {
		return nil, fmt.Errorf("证书指纹无效：%w", err)
	}
	cfg.Nick = strings.TrimSpace(cfg.Nick)
	if cfg.Nick == "" {
		return nil, errors.New("昵称不能为空")
	}
	if cfg.Password == "" {
		return nil, errors.New("密码不能为空")
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // pinning below replaces CA/hostname validation
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("服务器没有提供证书")
			}
			got, err := secure.NormalizeFingerprint(secure.Fingerprint(rawCerts[0]))
			if err != nil {
				return err
			}
			if got != pin {
				return fmt.Errorf("%w：收到 %s，期望 %s", ErrPinMismatch, got, pin)
			}
			return nil
		},
	}
	dialer := websocket.Dialer{
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: handshakeWait,
		Proxy:            http.ProxyFromEnvironment,
		NetDialContext:   (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
	}
	conn, resp, err := dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("连接服务器失败：%w（HTTP %s）", err, resp.Status)
		}
		return nil, fmt.Errorf("连接服务器失败：%w", err)
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()

	clientNonce := make([]byte, 32)
	if _, err := rand.Read(clientNonce); err != nil {
		return nil, err
	}
	hello, _ := protocol.NewDataEnvelope(protocol.TypeHello, protocol.Hello{
		Version: protocol.Version,
		Nick:    cfg.Nick,
		Nonce:   protocol.B64(clientNonce),
		Client:  "ctfbb-client/" + Version,
	})
	if err := writeText(conn, hello); err != nil {
		return nil, fmt.Errorf("发送登录请求失败：%w", err)
	}
	chEnv, err := readText(conn)
	if err != nil {
		return nil, fmt.Errorf("读取登录挑战失败：%w", err)
	}
	if chEnv.Type == protocol.TypeError {
		return nil, errors.New(chEnv.Error)
	}
	var challenge protocol.Challenge
	if err := protocol.Decode(chEnv, &challenge); err != nil {
		return nil, err
	}
	if challenge.Version != protocol.Version {
		return nil, fmt.Errorf("服务器协议版本 %d 与客户端 %d 不匹配", challenge.Version, protocol.Version)
	}
	if challenge.Iterations < secure.MinIterations {
		return nil, errors.New("服务器要求过弱的密钥派生参数，拒绝连接")
	}
	salt, err := protocol.UnB64(challenge.Salt, 16)
	if err != nil {
		return nil, err
	}
	serverNonce, err := protocol.UnB64(challenge.Nonce, 32)
	if err != nil {
		return nil, err
	}
	master, err := secure.DeriveLoginKey(cfg.Password, salt, challenge.Iterations)
	if err != nil {
		return nil, err
	}
	auth, _ := protocol.NewDataEnvelope(protocol.TypeAuth, protocol.Auth{
		Proof: protocol.B64(secure.ClientProof(master, cfg.Nick, clientNonce, serverNonce)),
	})
	if err := writeText(conn, auth); err != nil {
		return nil, fmt.Errorf("发送认证失败：%w", err)
	}
	welcomeEnv, err := readText(conn)
	if err != nil {
		return nil, fmt.Errorf("读取认证结果失败：%w", err)
	}
	if welcomeEnv.Type == protocol.TypeError {
		return nil, errors.New(welcomeEnv.Error)
	}
	var welcome protocol.Welcome
	if err := protocol.Decode(welcomeEnv, &welcome); err != nil {
		return nil, err
	}
	gotProof, err := protocol.UnB64(welcome.Proof, 32)
	if err != nil {
		return nil, errors.New("服务器证明格式错误")
	}
	if !secure.VerifyMAC(secure.ServerProof(master, cfg.Nick, clientNonce, serverNonce), gotProof) {
		return nil, errors.New("服务器身份验证失败（密码或握手被篡改）")
	}

	c2s, s2c, err := secure.SessionKeys(master, cfg.Nick, clientNonce, serverNonce)
	if err != nil {
		return nil, err
	}
	sendCipher, err := secure.NewFrameCipher(c2s, secure.DirectionClientToServer)
	if err != nil {
		return nil, err
	}
	recvCipher, err := secure.NewFrameCipher(s2c, secure.DirectionServerToClient)
	if err != nil {
		return nil, err
	}

	c := &Client{
		conn:    conn,
		send:    sendCipher,
		recv:    recvCipher,
		events:  cfg.OnEvent,
		pending: map[string]chan protocol.Envelope{},
		done:    make(chan struct{}),
	}
	conn.SetReadLimit(int64(secure.MaxFrameSize + secure.FrameOverhead + 4096))
	_ = conn.SetReadDeadline(time.Now().Add(readWait))
	conn.SetPingHandler(func(appData string) error {
		_ = conn.SetReadDeadline(time.Now().Add(readWait))
		err := conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(writeWait))
		if errors.Is(err, websocket.ErrCloseSent) {
			return nil
		}
		return err
	})
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(readWait))
	})
	success = true
	go c.readLoop()
	return c, nil
}

// Request sends one command and waits for its response.
func (c *Client) Request(cmd string, args any, timeout time.Duration) (json.RawMessage, error) {
	argRaw, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	return c.RequestRaw(cmd, argRaw, timeout)
}

// RequestRaw is Request with pre-encoded arguments.
func (c *Client) RequestRaw(cmd string, argRaw json.RawMessage, timeout time.Duration) (json.RawMessage, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if len(argRaw) == 0 {
		argRaw = json.RawMessage("{}")
	}
	id := fmt.Sprintf("%d", c.nextID.Add(1))
	req := protocol.Request{Cmd: cmd, Args: argRaw}
	reqRaw, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	env := protocol.Envelope{Type: protocol.TypeRequest, ID: id, Data: reqRaw}
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}

	ch := make(chan protocol.Envelope, 1)
	c.pendMu.Lock()
	c.pending[id] = ch
	c.pendMu.Unlock()
	defer func() {
		c.pendMu.Lock()
		delete(c.pending, id)
		c.pendMu.Unlock()
	}()

	c.writeMu.Lock()
	frames, err := protocol.SplitLimit(raw, protocol.ClientRequestMax)
	if err == nil {
		for _, frameRaw := range frames {
			var frame []byte
			frame, err = c.send.Seal(frameRaw)
			if err != nil {
				break
			}
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err = c.conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
				break
			}
		}
	}
	c.writeMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("发送失败：%w", err)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case resp := <-ch:
		if !resp.OK {
			if resp.Error == "" {
				resp.Error = "服务器拒绝了请求"
			}
			return nil, errors.New(resp.Error)
		}
		return resp.Data, nil
	case <-c.done:
		return nil, c.Err()
	case <-timer.C:
		return nil, errors.New("请求超时")
	}
}

// Close closes the connection. It is safe to call more than once.
func (c *Client) Close() error {
	c.finish(errors.New("连接已关闭"))
	return nil
}

// Done is closed when the session ends.
func (c *Client) Done() <-chan struct{} { return c.done }

// Err returns the reason the session ended, if any.
func (c *Client) Err() error {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	if c.err != nil {
		return c.err
	}
	return errors.New("连接已断开")
}

func (c *Client) readLoop() {
	var closeErr error
	defer func() {
		c.finish(closeErr)
	}()
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(readWait))
		mt, data, err := c.conn.ReadMessage()
		if err != nil {
			closeErr = err
			return
		}
		if mt != websocket.BinaryMessage {
			closeErr = errors.New("服务器发来非加密帧")
			return
		}
		if len(data) > secure.MaxFrameSize+secure.FrameOverhead {
			closeErr = errors.New("服务器帧过大")
			return
		}
		plain, err := c.recv.Open(data)
		if err != nil {
			closeErr = fmt.Errorf("解密失败：%w", err)
			return
		}
		message, complete, err := c.assembler.Add(plain)
		if err != nil {
			closeErr = fmt.Errorf("分片重组失败：%w", err)
			return
		}
		if !complete {
			continue
		}
		var env protocol.Envelope
		if err := json.Unmarshal(message, &env); err != nil {
			closeErr = fmt.Errorf("协议格式错误：%w", err)
			return
		}
		switch env.Type {
		case protocol.TypeEvent:
			if c.events != nil {
				c.events(env)
			}
		case protocol.TypeResponse:
			c.pendMu.Lock()
			ch := c.pending[env.ReplyTo]
			c.pendMu.Unlock()
			if ch != nil {
				select {
				case ch <- env:
				default:
				}
			}
		}
	}
}

func (c *Client) finish(err error) {
	c.closeOnce.Do(func() {
		c.errMu.Lock()
		c.err = err
		c.errMu.Unlock()
		close(c.done)
		_ = c.conn.Close()
	})
}

func writeText(conn *websocket.Conn, env protocol.Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
	return conn.WriteMessage(websocket.TextMessage, data)
}

func readText(conn *websocket.Conn) (protocol.Envelope, error) {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeWait))
	mt, data, err := conn.ReadMessage()
	if err != nil {
		return protocol.Envelope{}, err
	}
	if mt != websocket.TextMessage {
		return protocol.Envelope{}, errors.New("服务器握手使用了错误的帧类型")
	}
	if len(data) > 16<<10 {
		return protocol.Envelope{}, errors.New("服务器握手帧过大")
	}
	var env protocol.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return protocol.Envelope{}, err
	}
	return env, nil
}
