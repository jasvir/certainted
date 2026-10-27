package model

import "time"

// DestinationEvent is collector-supplied metadata. Missing hostname and workload remain missing.
type DestinationEvent struct {
	ID                  int64     `json:"id"`
	Time                time.Time `json:"time"`
	Collector           string    `json:"collector"`
	Vantage             string    `json:"vantage"`
	Hostname            string    `json:"hostname,omitempty"`
	IP                  string    `json:"ip,omitempty"`
	Port                int       `json:"port"`
	Workload            string    `json:"workload,omitempty"`
	AttributionReliable bool      `json:"attribution_reliable,omitempty"`
}

type Certificate struct {
	Fingerprint                   string    `json:"fingerprint_sha256"`
	SPKIFingerprint               string    `json:"spki_sha256"`
	Subject                       string    `json:"subject"`
	Issuer                        string    `json:"issuer"`
	SubjectNameSHA256             string    `json:"subject_name_sha256,omitempty"`
	IssuerNameSHA256              string    `json:"issuer_name_sha256,omitempty"`
	SubjectKeyIdentifier          string    `json:"subject_key_identifier,omitempty"`
	AuthorityKeyIdentifier        string    `json:"authority_key_identifier,omitempty"`
	VerifiedIssuerSPKIFingerprint string    `json:"verified_issuer_spki_sha256,omitempty"`
	Serial                        string    `json:"serial"`
	NotBefore                     time.Time `json:"not_before"`
	NotAfter                      time.Time `json:"not_after"`
	DNSNames                      []string  `json:"dns_names,omitempty"`
	IPAddresses                   []string  `json:"ip_addresses,omitempty"`
	EmailAddresses                []string  `json:"email_addresses,omitempty"`
	URIs                          []string  `json:"uris,omitempty"`
	IsCA                          bool      `json:"is_ca"`
	BasicConstraintsValid         bool      `json:"basic_constraints_valid"`
	MaxPathLen                    int       `json:"max_path_len"`
	MaxPathLenZero                bool      `json:"max_path_len_zero"`
	KeyUsage                      int       `json:"key_usage"`
	SelfSigned                    bool      `json:"self_signed"`
	PublicKeyAlgorithm            string    `json:"public_key_algorithm"`
	KeyBits                       int       `json:"key_bits,omitempty"`
	Source                        string    `json:"source"` // presented or trust_store
}

type CandidatePath struct {
	Certificates []Certificate `json:"certificates"`
	Validation   string        `json:"validation"`
}

type ProbeObservation struct {
	ID              int64           `json:"id"`
	DestinationID   int64           `json:"destination_id"`
	Time            time.Time       `json:"time"`
	Vantage         string          `json:"vantage"`
	Hostname        string          `json:"hostname,omitempty"`
	TargetIP        string          `json:"target_ip,omitempty"`
	Port            int             `json:"port"`
	SNI             string          `json:"sni,omitempty"`
	TLSVersion      string          `json:"tls_version,omitempty"`
	CipherSuite     string          `json:"cipher_suite,omitempty"`
	Presented       []Certificate   `json:"presented,omitempty"`
	CandidatePaths  []CandidatePath `json:"candidate_paths,omitempty"`
	TrustStore      string          `json:"trust_store,omitempty"`
	ValidationError string          `json:"validation_error,omitempty"`
	Failure         string          `json:"failure,omitempty"`
	IncompleteChain bool            `json:"incomplete_chain,omitempty"`
}

type WatchEntry struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	Group         string     `json:"group,omitempty"`
	MatchType     string     `json:"match_type"` // cert_sha256, spki_sha256, name
	Value         string     `json:"value"`
	Status        string     `json:"status"`
	Severity      string     `json:"severity"`
	Reason        string     `json:"reason,omitempty"`
	Source        string     `json:"source,omitempty"`
	EffectiveFrom *time.Time `json:"effective_from,omitempty"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`
}

type Finding struct {
	ID                     int64     `json:"id"`
	WatchID                int64     `json:"watch_id"`
	ProbeID                int64     `json:"probe_id"`
	DestinationID          int64     `json:"destination_id"`
	Evidence               string    `json:"evidence"` // direct, candidate, name_only
	CertificateFingerprint string    `json:"certificate_fingerprint"`
	Time                   time.Time `json:"time"`
}
