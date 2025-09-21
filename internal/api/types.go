package api

import (
	"net/url"

	apigen "github.com/ensigniasec/run-mcp/internal/api-gen"
)

// RatingResult abstracts 200 vs 202 for single-rating endpoints using apigen types.
type RatingResult struct {
	Rating     *apigen.SecurityRating // i.e. 200 response
	InProgress *apigen.ScanInProgress // i.e. 202 response
}

// RatingTarget is a closed set of supported target types.
// Implementations are small value types with validation via constructors.
// The discriminator uses the generated IdentifierKind to avoid duplication.
type RatingTarget interface {
	kind() apigen.IdentifierKind
}

// PURLTarget identifies a package via purl.
type PURLTarget struct{ PURL string }

// NewPURLTarget validates basic non-empty purl input.
func NewPURLTarget(purl string) (PURLTarget, error) { //nolint:ireturn
	if purl == "" {
		return PURLTarget{}, ErrValidation
	}
	return PURLTarget{PURL: purl}, nil
}

func (PURLTarget) kind() apigen.IdentifierKind { return apigen.Purl }

// RepoTarget identifies a repo by organization and name.
type RepoTarget struct{ Org, Repo string }

// NewRepoTarget validates non-empty org and repo.
func NewRepoTarget(org, repo string) (RepoTarget, error) { //nolint:ireturn
	if org == "" || repo == "" {
		return RepoTarget{}, ErrValidation
	}
	return RepoTarget{Org: org, Repo: repo}, nil
}

func (RepoTarget) kind() apigen.IdentifierKind { return apigen.Repo }

// OCITarget identifies an OCI ref.
type OCITarget struct{ Ref string }

// NewOCITarget validates non-empty ref.
func NewOCITarget(ref string) (OCITarget, error) { //nolint:ireturn
	if ref == "" {
		return OCITarget{}, ErrValidation
	}
	return OCITarget{Ref: ref}, nil
}

func (OCITarget) kind() apigen.IdentifierKind { return apigen.Oci }

// URLTarget identifies a raw URL string.
type URLTarget struct{ URL string }

// NewURLTarget validates non-empty URL and enforces http(s) scheme only.
func NewURLTarget(u string) (URLTarget, error) { //nolint:ireturn
	if u == "" {
		return URLTarget{}, ErrValidation
	}

	parsed, err := url.Parse(u)
	if err != nil {
		return URLTarget{}, ErrValidation
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return URLTarget{}, ErrValidation
	}
	if parsed.Host == "" { // ensure not a scheme-only or relative URL
		return URLTarget{}, ErrValidation
	}

	return URLTarget{URL: u}, nil
}

func (URLTarget) kind() apigen.IdentifierKind { return apigen.Url }
