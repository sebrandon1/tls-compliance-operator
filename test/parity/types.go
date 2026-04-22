//go:build parity

package parity

// ScanResults is the top-level JSON output from the tls-scanner.
type ScanResults struct {
	Timestamp  string     `json:"timestamp"`
	TotalIPs   int        `json:"total_ips"`
	ScannedIPs int        `json:"scanned_ips"`
	IPResults  []IPResult `json:"ip_results"`
	ScanErrors []ScanError `json:"scan_errors,omitempty"`
}

type ScanError struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	ErrorType string `json:"error_type"`
	ErrorMsg  string `json:"error_message"`
}

type IPResult struct {
	IP          string       `json:"ip"`
	Status      string       `json:"status"`
	OpenPorts   []int        `json:"open_ports"`
	PortResults []PortResult `json:"port_results"`
	Error       string       `json:"error,omitempty"`
}

type PortResult struct {
	Port            int              `json:"port"`
	Protocol        string           `json:"protocol"`
	State           string           `json:"state"`
	Service         string           `json:"service"`
	TlsVersions     []string         `json:"tls_versions,omitempty"`
	TlsCiphers      []string         `json:"tls_ciphers,omitempty"`
	TlsKeyExchange  *KeyExchangeInfo `json:"tls_key_exchange,omitempty"`
	Status          string           `json:"status"`
	Reason          string           `json:"reason,omitempty"`
	TLS13Supported  bool             `json:"tls13_supported,omitempty"`
	MLKEMSupported  bool             `json:"mlkem_supported,omitempty"`
	MLKEMCiphers    []string         `json:"mlkem_kems,omitempty"`
	TLSReadiness    *TLSReadiness    `json:"tls_readiness,omitempty"`
}

type KeyExchangeInfo struct {
	Groups         []string        `json:"groups,omitempty"`
	ForwardSecrecy *ForwardSecrecy `json:"forward_secrecy,omitempty"`
}

type ForwardSecrecy struct {
	Supported bool     `json:"supported"`
	ECDHE     []string `json:"ecdhe,omitempty"`
	KEMs      []string `json:"kems,omitempty"`
}

type TLSReadiness struct {
	TLS13Offered bool     `json:"tls13_offered"`
	TLS12Only    bool     `json:"tls12_only"`
	PQCCapable   bool     `json:"pqc_capable"`
	MLKEMKEMs    []string `json:"mlkem_kems,omitempty"`
	Notes        string   `json:"notes,omitempty"`
}

// NormalizedResult is the common schema both tool outputs are converted into
// for comparison.
type NormalizedResult struct {
	Endpoint string
	Reachable bool
	TLSDetected bool
	TLS10       bool
	TLS11       bool
	TLS12       bool
	TLS13       bool
	MTLSRequired bool

	// Fields from the operator only (gap report)
	ForwardSecrecy   *bool
	PQCReady         *bool
	CipherGrade      string
	KeyExchangeTypes map[string]string
	NegotiatedCurves map[string]string
	CertIssuer       string
	CertDaysToExpiry *int

	// Fields from the scanner only (gap report)
	CipherSuites   []string
	MLKEMSupported *bool
}

// ParityComparison holds the result of comparing two NormalizedResults.
type ParityComparison struct {
	Scenario     string
	Matches      []string
	Mismatches   []string
	OperatorOnly []string
	ScannerOnly  []string
}

// Scenario defines a test pod configuration and expected outcomes.
type Scenario struct {
	Name         string
	PodName      string
	Env          map[string]string
	Port         int
	ExpectTLS    bool
	ExpectMTLS   bool
}
