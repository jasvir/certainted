// Package probe makes independent TLS connections to destinations reported by
// collectors. It never participates in an application's TLS connection.
package probe

import (
	"bytes"
	"context"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jasvir/certainted/internal/model"
)

const (
	defaultTimeout             = 8 * time.Second
	defaultMaxCertificates     = 16
	defaultMaxCertificateBytes = 256 * 1024
)

// Config controls an independent probe. A custom PEM replaces system roots
// unless UseSystemRoots is true. With no custom PEM, system roots are used.
// DialContext is intended for controlled network transports and tests; it
// must establish a fresh connection and must never convey application data.
type Config struct {
	Timeout             time.Duration
	TrustStorePath      string
	TrustStorePEM       []byte
	TrustStoreName      string
	UseSystemRoots      bool
	MaxCertificates     int
	MaxCertificateBytes int
	// AllowIP is an optional scope gate applied before TCP connection. The
	// scheduler should supply the configured destination policy here.
	AllowIP     func(net.IP) bool
	DialContext func(context.Context, string, string) (net.Conn, error)
}

// Probe returns evidence from a separate TLS handshake. The connection is
// deliberately not used to send HTTP or any other application protocol data.
// Certificate retrieval is separate from path validation so invalid chains
// can still be recorded. Caller policy must authorize the destination event
// and pass its IP scope rule through Config.AllowIP; Probe checks the resolved
// IP before dialing it.
func Probe(ctx context.Context, event model.DestinationEvent, cfg Config) model.ProbeObservation {
	result := model.ProbeObservation{
		DestinationID: event.ID,
		Time:          time.Now().UTC(),
		Vantage:       event.Vantage,
		Hostname:      event.Hostname,
		TargetIP:      event.IP,
		Port:          event.Port,
	}
	if err := validateDestination(event); err != nil {
		result.Failure = err.Error()
		return result
	}

	name := event.Hostname
	if name == "" {
		name = event.IP
	}
	// Go's TLS client sends SNI only for DNS names, never IP literals.
	if net.ParseIP(name) == nil {
		result.SNI = name
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	targetIP, err := resolveTarget(probeCtx, event, cfg.AllowIP)
	if err != nil {
		result.Failure = fmt.Sprintf("target resolution or policy: %v", err)
		return result
	}
	// Dial the resolved address rather than resolving a hostname again inside
	// DialContext. This prevents a second DNS answer from changing the target.
	result.TargetIP = targetIP.String()
	address := net.JoinHostPort(result.TargetIP, strconv.Itoa(event.Port))
	dial := cfg.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	raw, err := dial(probeCtx, "tcp", address)
	if err != nil {
		result.Failure = fmt.Sprintf("TCP connection: %v", err)
		return result
	}
	defer raw.Close()
	if remote, ok := raw.RemoteAddr().(*net.TCPAddr); ok && remote.IP != nil {
		if !remote.IP.Equal(targetIP) {
			result.Failure = "TCP connection reached an unexpected target IP"
			return result
		}
		result.TargetIP = remote.IP.String()
	}

	maxCerts := cfg.MaxCertificates
	if maxCerts <= 0 {
		maxCerts = defaultMaxCertificates
	}
	maxBytes := cfg.MaxCertificateBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxCertificateBytes
	}
	// InsecureSkipVerify applies only to this independent connection. It lets
	// us retain the presented certificates even if later validation fails.
	// x509.Verify below performs validation against the configured trust store.
	conn := tls.Client(raw, &tls.Config{
		ServerName:         name,
		InsecureSkipVerify: true, // independent evidence collection; verified below
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) > maxCerts {
				return fmt.Errorf("server presented %d certificates; limit is %d", len(rawCerts), maxCerts)
			}
			var total int
			for _, der := range rawCerts {
				total += len(der)
				if total > maxBytes {
					return fmt.Errorf("server certificate data exceeds %d bytes", maxBytes)
				}
			}
			return nil
		},
	})
	defer conn.Close()
	if err := conn.HandshakeContext(probeCtx); err != nil {
		result.Failure = fmt.Sprintf("TLS handshake: %v", err)
		// PeerCertificates can be populated before a local certificate-limit
		// callback rejects the handshake. Do not store a truncated chain.
		return result
	}

	state := conn.ConnectionState()
	result.TLSVersion = tls.VersionName(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	if len(state.PeerCertificates) == 0 {
		result.Failure = "TLS handshake returned no peer certificates"
		return result
	}
	for _, cert := range state.PeerCertificates {
		described := describeCertificate(cert, "presented")
		// A presented issuer can verify this certificate even when the whole
		// path does not validate against the configured trust store.
		described.VerifiedIssuerSPKIFingerprint = verifiedIssuerSPKI(cert, state.PeerCertificates)
		result.Presented = append(result.Presented, described)
	}

	roots, trustName, trustErr := loadTrustStore(cfg)
	result.TrustStore = trustName
	if trustErr != nil {
		result.ValidationError = fmt.Sprintf("trust store: %v", trustErr)
		return result
	}
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	paths, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       name,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime:   result.Time,
	})
	if err != nil {
		result.ValidationError = err.Error()
		var unknownAuthority x509.UnknownAuthorityError
		result.IncompleteChain = errors.As(err, &unknownAuthority) && hasUnresolvedIssuer(state.PeerCertificates)
		return result
	}
	presented := make(map[string]bool, len(state.PeerCertificates))
	for _, cert := range state.PeerCertificates {
		presented[string(cert.Raw)] = true
	}
	for _, path := range paths {
		candidate := model.CandidatePath{Validation: "verified"}
		for _, cert := range path {
			source := "trust_store"
			if presented[string(cert.Raw)] {
				source = "presented"
			}
			candidate.Certificates = append(candidate.Certificates, describeCertificate(cert, source))
		}
		result.CandidatePaths = append(result.CandidatePaths, candidate)
	}
	return result
}

func verifiedIssuerSPKI(cert *x509.Certificate, presented []*x509.Certificate) string {
	var verified string
	for _, issuer := range presented {
		if !bytes.Equal(cert.RawIssuer, issuer.RawSubject) || cert.CheckSignatureFrom(issuer) != nil {
			continue
		}
		fp := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
		current := hex.EncodeToString(fp[:])
		if verified != "" && verified != current {
			// Ambiguous issuer keys must not become a definitive CRL match.
			return ""
		}
		verified = current
	}
	return verified
}

func resolveTarget(ctx context.Context, event model.DestinationEvent, allow func(net.IP) bool) (net.IP, error) {
	if event.IP != "" {
		ip := net.ParseIP(event.IP)
		if allow != nil && !allow(ip) {
			return nil, errors.New("destination IP is outside probe scope")
		}
		return ip, nil
	}
	if ip := net.ParseIP(event.Hostname); ip != nil {
		if allow != nil && !allow(ip) {
			return nil, errors.New("destination IP is outside probe scope")
		}
		return ip, nil
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, event.Hostname)
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		if allow == nil || allow(address.IP) {
			return address.IP, nil
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("hostname resolved to no IP addresses")
	}
	return nil, errors.New("all resolved IP addresses are outside probe scope")
}

func validateDestination(event model.DestinationEvent) error {
	if event.Port < 1 || event.Port > 65535 {
		return errors.New("invalid destination port")
	}
	if event.Hostname == "" && event.IP == "" {
		return errors.New("missing destination hostname or IP")
	}
	if event.IP != "" && net.ParseIP(event.IP) == nil {
		return errors.New("invalid destination IP")
	}
	if event.Hostname != "" {
		if len(event.Hostname) > 253 || strings.TrimSpace(event.Hostname) != event.Hostname || strings.ContainsAny(event.Hostname, " /\\:@\x00\r\n\t") {
			return errors.New("invalid destination hostname")
		}
	}
	return nil
}

func loadTrustStore(cfg Config) (*x509.CertPool, string, error) {
	hasCustom := cfg.TrustStorePath != "" || len(cfg.TrustStorePEM) != 0
	useSystem := cfg.UseSystemRoots || !hasCustom
	name := cfg.TrustStoreName
	if name == "" {
		switch {
		case hasCustom && useSystem:
			name = "system + custom PEM"
		case hasCustom:
			name = "custom PEM"
		default:
			name = "system"
		}
	}
	var roots *x509.CertPool
	if useSystem {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, name, err
		}
	} else {
		roots = x509.NewCertPool()
	}
	if cfg.TrustStorePath != "" {
		pem, err := os.ReadFile(cfg.TrustStorePath)
		if err != nil {
			return nil, name, err
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, name, errors.New("PEM file contains no valid certificates")
		}
	}
	if len(cfg.TrustStorePEM) != 0 && !roots.AppendCertsFromPEM(cfg.TrustStorePEM) {
		return nil, name, errors.New("PEM bytes contain no valid certificates")
	}
	return roots, name, nil
}

func describeCertificate(cert *x509.Certificate, source string) model.Certificate {
	fp := sha256.Sum256(cert.Raw)
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	subjectName := sha256.Sum256(cert.RawSubject)
	issuerName := sha256.Sum256(cert.RawIssuer)
	described := model.Certificate{
		Fingerprint:            hex.EncodeToString(fp[:]),
		SPKIFingerprint:        hex.EncodeToString(spki[:]),
		Subject:                cert.Subject.String(),
		Issuer:                 cert.Issuer.String(),
		SubjectNameSHA256:      hex.EncodeToString(subjectName[:]),
		IssuerNameSHA256:       hex.EncodeToString(issuerName[:]),
		SubjectKeyIdentifier:   hex.EncodeToString(cert.SubjectKeyId),
		AuthorityKeyIdentifier: hex.EncodeToString(cert.AuthorityKeyId),
		Serial:                 cert.SerialNumber.Text(16),
		NotBefore:              cert.NotBefore,
		NotAfter:               cert.NotAfter,
		DNSNames:               append([]string(nil), cert.DNSNames...),
		EmailAddresses:         append([]string(nil), cert.EmailAddresses...),
		IsCA:                   cert.IsCA,
		BasicConstraintsValid:  cert.BasicConstraintsValid,
		MaxPathLen:             cert.MaxPathLen,
		MaxPathLenZero:         cert.MaxPathLenZero,
		KeyUsage:               int(cert.KeyUsage),
		SelfSigned:             isSelfSigned(cert),
		PublicKeyAlgorithm:     cert.PublicKeyAlgorithm.String(),
		Source:                 source,
	}
	for _, ip := range cert.IPAddresses {
		described.IPAddresses = append(described.IPAddresses, ip.String())
	}
	for _, uri := range cert.URIs {
		described.URIs = append(described.URIs, uri.String())
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		described.KeyBits = key.N.BitLen()
	case *ecdsa.PublicKey:
		described.KeyBits = key.Curve.Params().BitSize
	case ed25519.PublicKey:
		described.KeyBits = len(key) * 8
	case *dsa.PublicKey:
		described.KeyBits = key.P.BitLen()
	}
	return described
}

func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// hasUnresolvedIssuer detects an obvious gap in the presented list. Omitted
// trusted roots are normal, so this is only used when path validation fails.
func hasUnresolvedIssuer(presented []*x509.Certificate) bool {
	if len(presented) == 0 {
		return true
	}
	for i, cert := range presented {
		if isSelfSigned(cert) {
			continue
		}
		found := false
		for j, issuer := range presented {
			if i != j && cert.CheckSignatureFrom(issuer) == nil {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}
