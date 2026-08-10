package secrets

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
)

// EnvProvider reads a secret from an environment variable.
//
// Offered because it is what container platforms make easiest, and documented as the weakest
// option: environment variables are visible in process listings, in `docker inspect`, and in
// crash dumps. The file provider is the one to prefer.
type EnvProvider struct{}

// NewEnvProvider builds the environment-variable provider.
func NewEnvProvider() *EnvProvider { return &EnvProvider{} }

// Name implements Provider.
func (p *EnvProvider) Name() string { return "env" }

// Resolve implements Provider.
func (p *EnvProvider) Resolve(_ context.Context, ref string) ([]byte, error) {
	value, ok := os.LookupEnv(ref)
	if !ok {
		return nil, fmt.Errorf("secrets: environment variable %s is not set", ref)
	}
	return []byte(value), nil
}

// FileProvider reads a secret from a file, which is how Docker secrets, Kubernetes secret
// volumes and systemd credentials all present themselves.
type FileProvider struct{}

// NewFileProvider builds the file provider.
func NewFileProvider() *FileProvider { return &FileProvider{} }

// Name implements Provider.
func (p *FileProvider) Name() string { return "file" }

// Resolve implements Provider.
//
// A trailing newline is trimmed: every editor and every `echo` adds one, and a password with an
// invisible newline in it produces an authentication failure that takes an afternoon to find.
func (p *FileProvider) Resolve(_ context.Context, ref string) ([]byte, error) {
	info, err := os.Stat(ref)
	if err != nil {
		return nil, fmt.Errorf("secrets: %s: %w", ref, err)
	}
	if mode := info.Mode().Perm(); mode&fs.FileMode(0o044) != 0 {
		return nil, fmt.Errorf("secrets: %s is mode %#o; a credential file must not be readable by group or other", ref, mode)
	}
	raw, err := os.ReadFile(ref) //nolint:gosec // the path comes from the operator's own configuration
	if err != nil {
		return nil, fmt.Errorf("secrets: read %s: %w", ref, err)
	}
	return bytes.TrimRight(raw, "\r\n"), nil
}
