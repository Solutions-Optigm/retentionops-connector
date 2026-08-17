// Package enrollment turns a single-use token into a durable connector identity.
//
// It runs once, by hand, on the customer's host. Everything afterwards is signed with the key
// this package generates — and that key is generated here, locally, before the first network
// call, so there is no moment at which RetentionOps could have held it.
package enrollment

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/controlplane"
	"github.com/solutions-optigm/retentionops-connector/internal/identity"
	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
)

// Request is what the operator supplies on the command line.
type Request struct {
	ControlPlaneURL string
	OrganizationID  string
	Token           string
	Version         string
	CAFile          string
	Directory       string
}

// Run performs the enrollment exchange and writes the identity file.
//
// The pending private key is persisted before the request and reused on retry. The control plane
// accepts a consumed token only for that exact public key, so a failure while installing the final
// identity is resumable without making the token reusable by another party.
// explainTrust turns a TLS verification failure into the answer to "what do I do now".
//
// A self-hosted control plane usually presents a privately signed certificate, and Go reports
// that as "certificate signed by unknown authority" — accurate, and useless to somebody who has
// the certificate sitting in their home directory. The fix is one answer to one question in
// `init`, and this is where an operator finds out which question.
func explainTrust(err error, caFile string) error {
	var verification *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	if !errors.As(err, &verification) && !errors.As(err, &authority) && !errors.As(err, &hostname) {
		return err
	}
	if caFile != "" {
		return fmt.Errorf("enrollment: this host does not trust the control plane's certificate, "+
			"and the CA this bundle carries (%s) does not sign it: %w", caFile, err)
	}
	return fmt.Errorf("enrollment: this host does not trust the control plane's certificate. "+
		"A self-hosted control plane usually has a private one: run init again and supply its CA "+
		"certificate when asked, then install again with --repair: %w", err)
}

func Run(ctx context.Context, request Request) (*identity.Identity, error) {
	attempt, err := identity.LoadOrCreateEnrollmentAttempt(request.Directory, request.OrganizationID)
	if err != nil {
		return nil, err
	}

	client, err := controlplane.New(request.ControlPlaneURL, request.CAFile, request.Version, nil, 30*time.Second)
	if err != nil {
		return nil, err
	}
	// Published with the signing key so a console can seal a source configuration to this
	// connector without a second round trip. Derived from the same seed, so a retried enrolment
	// publishes the same key and an envelope sealed meanwhile still opens.
	encryptionKey, err := attempt.EncryptionKey()
	if err != nil {
		return nil, err
	}
	response, err := client.Enroll(ctx, protocolv1.EnrollmentRequest{
		ProtocolVersion:  protocolv1.Version,
		OrganizationID:   request.OrganizationID,
		Token:            request.Token,
		PublicKey:        identity.EncodePublic(attempt.PublicKey()),
		EncryptionKey:    identity.EncodePublicEncryption(encryptionKey.PublicKey()),
		ConnectorVersion: request.Version,
		Platform:         runtime.GOOS + "/" + runtime.GOARCH,
	})
	if err != nil {
		return nil, explainTrust(err, request.CAFile)
	}
	if response.OrganizationID != request.OrganizationID {
		return nil, fmt.Errorf("enrollment: the control plane answered for organization %s, not %s",
			response.OrganizationID, request.OrganizationID)
	}

	if err := identity.Save(request.Directory, attempt.PrivateKey(), identity.Enrollment{
		ConnectorID:           response.ConnectorID,
		OrganizationID:        response.OrganizationID,
		ControlPlanePublicKey: response.ControlPlanePublicKey,
		IssuedAt:              response.IssuedAt,
	}); err != nil {
		return nil, err
	}
	if err := identity.CompleteEnrollmentAttempt(request.Directory); err != nil {
		return nil, err
	}
	if err := config.RequireDirectoryIsPrivate(request.Directory); err != nil {
		return nil, err
	}
	return identity.Load(request.Directory)
}
