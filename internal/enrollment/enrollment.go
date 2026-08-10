// Package enrollment turns a single-use token into a durable connector identity.
//
// It runs once, by hand, on the customer's host. Everything afterwards is signed with the key
// this package generates — and that key is generated here, locally, before the first network
// call, so there is no moment at which RetentionOps could have held it.
package enrollment

import (
	"context"
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
// The order is deliberate: generate, send the public half, then persist. A failure at any point
// leaves no half-enrolled state — the operator retries with a fresh token, because the previous
// one was burned by the control plane the moment it was accepted.
func Run(ctx context.Context, request Request) (*identity.Identity, error) {
	public, private, err := identity.Generate()
	if err != nil {
		return nil, err
	}

	client, err := controlplane.New(request.ControlPlaneURL, request.CAFile, request.Version, nil, 30*time.Second)
	if err != nil {
		return nil, err
	}
	response, err := client.Enroll(ctx, protocolv1.EnrollmentRequest{
		ProtocolVersion:  protocolv1.Version,
		OrganizationID:   request.OrganizationID,
		Token:            request.Token,
		PublicKey:        identity.EncodePublic(public),
		ConnectorVersion: request.Version,
		Platform:         runtime.GOOS + "/" + runtime.GOARCH,
	})
	if err != nil {
		return nil, err
	}
	if response.OrganizationID != request.OrganizationID {
		return nil, fmt.Errorf("enrollment: the control plane answered for organization %s, not %s",
			response.OrganizationID, request.OrganizationID)
	}

	if err := identity.Save(request.Directory, private, identity.Enrollment{
		ConnectorID:           response.ConnectorID,
		OrganizationID:        response.OrganizationID,
		ControlPlanePublicKey: response.ControlPlanePublicKey,
		IssuedAt:              response.IssuedAt,
	}); err != nil {
		return nil, err
	}
	if err := config.RequireDirectoryIsPrivate(request.Directory); err != nil {
		return nil, err
	}
	return identity.Load(request.Directory)
}
