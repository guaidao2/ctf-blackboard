package server

import (
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/guaidao2/ctf-blackboard/internal/protocol"
	"github.com/guaidao2/ctf-blackboard/internal/secure"
)

const (
	writeWait   = 10 * time.Second
	pongWait    = 90 * time.Second
	pingPeriod  = 25 * time.Second
	maxOutbound = 256
)

// Client is one authenticated operator connection. The writer goroutine is the
// only goroutine that writes to the WebSocket, which keeps the frame sequence
// and the socket ordering consistent.
type Client struct {
	hub    *Hub
	conn   *websocket.Conn
	nick   string
	remote string
	joined time.Time
	log    *slog.Logger

	send   chan []byte
	cipher *secure.FrameCipher
	recv   *secure.FrameCipher

	assembler protocol.Assembler

	closeOnce sync.Once
	done      chan struct{}
	kicked    atomic.Bool

	chatMu     sync.Mutex
	chatWindow time.Time
	chatCount  int
}

func newClient(h *Hub, conn *websocket.Conn, nick, remote string, send, recv *secure.FrameCipher) *Client {
	return &Client{
		hub:    h,
		conn:   conn,
		nick:   nick,
		remote: remote,
		joined: time.Now().UTC(),
		log:    h.log.With("nick", nick, "remote", remote),
		send:   make(chan []byte, maxOutbound),
		cipher: send,
		recv:   recv,
		done:   make(chan struct{}),
		// Clients send tiny commands; cap inbound reassembly separately from
		// the snapshot-sized limit on the client side.
		assembler: protocol.Assembler{Max: protocol.ClientRequestMax},
	}
}

func (c *Client) start() {
	go c.writeLoop()
	go c.readLoop()
}

func (c *Client) readLoop() {
	defer c.hub.removeClient(c)

	for {
		mt, data, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		if c.kicked.Load() {
			return
		}
		if mt != websocket.BinaryMessage {
			c.log.Warn("unexpected non-binary frame after login")
			return
		}
		if len(data) > secure.MaxFrameSize+secure.FrameOverhead {
			c.log.Warn("oversize encrypted frame")
			return
		}
		plain, err := c.recv.Open(data)
		if err != nil {
			c.log.Warn("cannot decrypt frame", "err", err)
			return
		}
		message, complete, err := c.assembler.Add(plain)
		if err != nil {
			c.log.Warn("cannot reassemble message", "err", err)
			return
		}
		if !complete {
			continue
		}
		var env protocol.Envelope
		if err := json.Unmarshal(message, &env); err != nil {
			c.log.Warn("malformed request envelope", "err", err)
			return
		}
		if env.Type != protocol.TypeRequest {
			c.log.Warn("unexpected envelope type", "type", env.Type)
			return
		}
		var req protocol.Request
		if len(env.Data) > 0 {
			if err := json.Unmarshal(env.Data, &req); err != nil {
				c.enqueueResponse(protocol.NewErrorResponse(env.ID, "请求格式错误"))
				continue
			}
		}
		resp := c.hub.dispatch(c, req)
		resp.ReplyTo = env.ID
		c.enqueueResponse(resp)
	}
}

func (c *Client) enqueueResponse(env protocol.Envelope) {
	raw, err := json.Marshal(env)
	if err != nil {
		c.log.Error("cannot encode response", "err", err)
		return
	}
	c.enqueue(raw)
}

func (c *Client) enqueue(raw []byte) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.send <- raw:
		return true
	default:
		// A slow client must not block the hub. Drop it; it can reconnect and
		// fetch a fresh snapshot.
		c.log.Warn("outbound queue full; disconnecting slow client")
		c.close()
		return false
	}
}

func (c *Client) writeLoop() {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()
	defer c.close()

	for {
		select {
		case <-c.done:
			return
		case raw := <-c.send:
			frames, err := protocol.Split(raw)
			if err != nil {
				c.log.Warn("cannot fragment message", "err", err)
				c.writeProtocolError("服务器消息超过传输上限，连接将关闭")
				return
			}
			for _, frameRaw := range frames {
				frame, err := c.cipher.Seal(frameRaw)
				if err != nil {
					c.log.Warn("cannot encrypt frame", "err", err)
					return
				}
				_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
				if err := c.conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
					return
				}
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait)); err != nil {
				return
			}
		}
	}
}

func (c *Client) writeProtocolError(text string) {
	env, err := protocol.NewEvent(protocol.EventError, map[string]string{"message": text})
	if err != nil {
		return
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return
	}
	frame, err := c.cipher.Seal(raw)
	if err != nil {
		return
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
	_ = c.conn.WriteMessage(websocket.BinaryMessage, frame)
}

func (c *Client) close() {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.conn.Close()
	})
}

// allowChat is a small per-connection flood guard: 8 messages per 3 seconds.
func (c *Client) allowChat(now time.Time) bool {
	c.chatMu.Lock()
	defer c.chatMu.Unlock()
	if now.Sub(c.chatWindow) > 3*time.Second {
		c.chatWindow = now
		c.chatCount = 0
	}
	c.chatCount++
	return c.chatCount <= 8
}
