package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/guaidao2/ctf-blackboard/internal/secure"
)

// ProbeFingerprint performs a TLS handshake without trusting the certificate
// and returns its SHA-256 fingerprint. It is used for the first-connection
// "trust this fingerprint?" prompt, before any password material is sent.
func ProbeFingerprint(ctx context.Context, rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "wss" || u.Host == "" {
		return "", fmt.Errorf("服务器地址必须是 wss://…/ws")
	}
	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}

	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return "", fmt.Errorf("连接服务器失败：%w", err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // fingerprint is captured for the user to confirm
		ServerName:         u.Hostname(),
		NextProtos:         []string{"http/1.1"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("TLS 握手失败：%w", err)
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("服务器没有提供证书")
	}
	return secure.Fingerprint(certs[0].Raw), nil
}
