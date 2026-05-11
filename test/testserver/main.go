package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var tlsVersionMap = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

func main() {
	cfg := loadConfig()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":       "ok",
			"tls_enabled":  cfg.tlsEnabled,
			"min_version":  cfg.minVersion,
			"max_version":  cfg.maxVersion,
			"mtls":         cfg.mtlsRequired,
			"port":         cfg.port,
			"cert_expired": cfg.certExpired,
			"cert_cn":      cfg.certCN,
		})
	})

	addr := fmt.Sprintf(":%d", cfg.port)

	if !cfg.tlsEnabled {
		log.Printf("Serving plain HTTP on %s", addr)
		log.Fatal(http.ListenAndServe(addr, mux))
		return
	}

	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		log.Fatalf("Failed to build TLS config: %v", err)
	}

	server := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	log.Printf("Serving TLS on %s (min=%s max=%s mtls=%v expired=%v cn=%s)", addr, cfg.minVersion, cfg.maxVersion, cfg.mtlsRequired, cfg.certExpired, cfg.certCN)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

type config struct {
	minVersion      string
	maxVersion      string
	tlsEnabled      bool
	mtlsRequired    bool
	port            int
	certExpired     bool
	certExpiryHours int
	certCN          string
}

func loadConfig() config {
	cfg := config{
		minVersion:   envOrDefault("TLS_MIN_VERSION", "1.2"),
		maxVersion:   envOrDefault("TLS_MAX_VERSION", "1.3"),
		tlsEnabled:   envOrDefault("TLS_ENABLED", "true") == "true",
		mtlsRequired: envOrDefault("MTLS_REQUIRED", "false") == "true",
		certExpired:  envOrDefault("CERT_EXPIRED", "false") == "true",
		certCN:       envOrDefault("CERT_CN", "tls-test-server"),
	}

	if h := os.Getenv("CERT_EXPIRY_HOURS"); h != "" {
		v, err := strconv.Atoi(h)
		if err != nil {
			log.Fatalf("Invalid CERT_EXPIRY_HOURS: %s", h)
		}
		cfg.certExpiryHours = v
	}

	portStr := os.Getenv("LISTEN_PORT")
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil {
			log.Fatalf("Invalid LISTEN_PORT: %s", portStr)
		}
		cfg.port = p
	} else if cfg.tlsEnabled {
		cfg.port = 8443
	} else {
		cfg.port = 8080
	}

	return cfg
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func buildTLSConfig(cfg config) (*tls.Config, error) {
	minVer, ok := tlsVersionMap[cfg.minVersion]
	if !ok {
		return nil, fmt.Errorf("unknown TLS min version: %s", cfg.minVersion)
	}
	maxVer, ok := tlsVersionMap[cfg.maxVersion]
	if !ok {
		return nil, fmt.Errorf("unknown TLS max version: %s", cfg.maxVersion)
	}

	serverCert, err := generateSelfSignedCert(cfg)
	if err != nil {
		return nil, fmt.Errorf("generating server cert: %w", err)
	}

	tlsCfg := &tls.Config{
		MinVersion:   minVer,
		MaxVersion:   maxVer,
		Certificates: []tls.Certificate{serverCert},
	}

	if cfg.mtlsRequired {
		clientCA, err := generateCA("client-ca")
		if err != nil {
			return nil, fmt.Errorf("generating client CA: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(clientCA.cert)
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsCfg, nil
}

type caBundle struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func generateCA(cn string) (*caBundle, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &caBundle{cert: cert, key: key}, nil
}

func generateSelfSignedCert(cfg config) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	sans := []string{
		"localhost",
		"*.parity-test.svc.cluster.local",
		"*.parity-test.svc",
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := time.Now().Add(10 * 365 * 24 * time.Hour)

	if cfg.certExpired {
		notBefore = time.Now().Add(-48 * time.Hour)
		notAfter = time.Now().Add(-1 * time.Hour)
	} else if cfg.certExpiryHours > 0 {
		notAfter = time.Now().Add(time.Duration(cfg.certExpiryHours) * time.Hour)
	}

	template := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: cfg.certCN},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	// Also add any IPs from SAN_IPS env var (for pod IP coverage)
	if extraIPs := os.Getenv("SAN_IPS"); extraIPs != "" {
		for _, ipStr := range strings.Split(extraIPs, ",") {
			if ip := net.ParseIP(strings.TrimSpace(ipStr)); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			}
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func newSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("Failed to generate serial: %v", err)
	}
	return serial
}
