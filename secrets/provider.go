// Package secrets resolves credential references to credential values, inside the customer's
// network.
//
// This package is the reason RetentionOps never holds a database password. The control plane
// knows a data source exists and what it is called; the value behind that source's credential
// reference is fetched here, by the customer's own connector, using the customer's own secret
// manager, and is never transmitted anywhere.
package secrets

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Provider resolves one reference to one secret value.
//
// Implementations must never log the value, never write it to disk, and never include it in an
// error. The interface is this narrow on purpose: there is nowhere for a provider to return
// anything except the bytes the caller asked for.
type Provider interface {
	// Name is the identifier used in the "provider" field of a configuration file.
	Name() string
	// Resolve returns the secret value for ref.
	Resolve(ctx context.Context, ref string) ([]byte, error)
}

// Registry is the set of providers this build supports.
type Registry struct {
	providers map[string]Provider
}

// NewRegistry assembles the providers compiled into this build.
func NewRegistry(providers ...Provider) *Registry {
	registry := &Registry{providers: make(map[string]Provider, len(providers))}
	for _, provider := range providers {
		registry.providers[provider.Name()] = provider
	}
	return registry
}

// Default is the registry the connector runs with.
func Default() *Registry {
	return NewRegistry(NewEnvProvider(), NewFileProvider(), NewAWSSecretsManagerProvider(""))
}

// Names lists the supported providers, for error messages and for `doctor`.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Resolve fetches a secret through the named provider.
//
// An unknown provider is an error rather than a fallback. Falling back would mean a typo in a
// configuration file silently changes where a production credential is read from.
func (r *Registry) Resolve(ctx context.Context, provider, ref string) ([]byte, error) {
	implementation, ok := r.providers[provider]
	if !ok {
		return nil, fmt.Errorf("secrets: unknown provider %q; this build supports %s",
			provider, strings.Join(r.Names(), ", "))
	}
	value, err := implementation.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("secrets: %s resolved %q to an empty value", provider, ref)
	}
	return value, nil
}

// Supports reports whether a provider name is known to this build. Used by `validate-config`
// so a deployment fails at configuration time rather than at the first job.
func (r *Registry) Supports(provider string) bool {
	_, ok := r.providers[provider]
	return ok
}
