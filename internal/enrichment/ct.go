// Package enrichment defines optional, external evidence sources. No such
// source is invoked by the Phase 1 observer.
package enrichment

import (
	"context"
	"time"
)

// CTEvidence is public issuance evidence, never evidence that an application
// encountered or trusted the certificate.
type CTEvidence struct {
	CertificateFingerprint string
	LogID                  string
	LoggedAt               time.Time
	Source                 string
}

// CTProvider may be implemented later behind an explicit opt-in, bounded
// lookup policy that records provenance and metadata disclosure.
type CTProvider interface {
	Lookup(ctx context.Context, certificateFingerprint string) ([]CTEvidence, error)
}
