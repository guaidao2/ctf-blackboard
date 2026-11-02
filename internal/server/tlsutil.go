package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/guaidao2/ctf-blackboard/internal/secure"
)

const (
	defaultCertName = "server.crt"
	defaultKeyName  = "server.key"
)

// loadOrCreateCertificate returns the server certificate and its SHA-256
// fingerprint. Without explicit paths, a self-signed certificate is generated
// once in the data directory and reused on later starts (so the pin stays
// stable unless the operator deletes it).
func loadOrCreateCertificate(dataDir, certFile, keyFile string) (tls.Certificate, string, string, string, error) {
	if certFile == "" && keyFile == "" {
		certFile = filepath.Join(dataDir, defaultCertName)
		keyFile = filepath.Join(dataDir, defaultKeyName)
	}
	certExists := fileExists(certFile)
	keyExists := fileExists(keyFile)

	switch {
	case certExists && keyExists:
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return tls.Certificate{}, "", "", "", fmt.Errorf("load TLS certificate: %w", err)
		}
		if len(cert.Certificate) == 0 {
			return tls.Certificate{}, "", "", "", fmt.Errorf("TLS certificate chain is empty")
		}
		return cert, secure.Fingerprint(cert.Certificate[0]), certFile, keyFile, nil
	case certExists != keyExists:
		return tls.Certificate{}, "", "", "", fmt.Errorf("TLS certificate and key must both exist (%s, %s)", certFile, keyFile)
	default:
		certPEM, keyPEM, err := generateSelfSigned()
		if err != nil {
			return tls.Certificate{}, "", "", "", err
		}
		if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
			return tls.Certificate{}, "", "", "", err
		}
		if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
			return tls.Certificate{}, "", "", "", fmt.Errorf("write TLS key: %w", err)
		}
		if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
			return tls.Certificate{}, "", "", "", fmt.Errorf("write TLS certificate: %w", err)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return tls.Certificate{}, "", "", "", fmt.Errorf("parse generated certificate: %w", err)
		}
		return cert, secure.Fingerprint(cert.Certificate[0]), certFile, keyFile, nil
	}
}

func generateSelfSigned() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate TLS key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	hostname, _ := os.Hostname()
	dnsNames := []string{"localhost"}
	if hostname != "" && !strings.EqualFold(hostname, "localhost") {
		dnsNames = append(dnsNames, hostname)
	}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	ips = append(ips, localIPv4s()...)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "CTF Blackboard",
			Organization: []string{"CTF Blackboard"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal TLS key: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func localIPv4s() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 != nil && !ip4.IsLoopback() {
				out = append(out, ip4)
			}
		}
	}
	return out
}

func bestHost() string {
	if ips := localIPv4s(); len(ips) > 0 {
		return ips[0].String()
	}
	return "127.0.0.1"
}
