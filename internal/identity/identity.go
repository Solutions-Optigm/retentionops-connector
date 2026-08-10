// Package identity holds the connector's key pair and the control-plane key it has pinned.
//
// The private key is generated on the customer's host during enrollment and has no
// representation anywhere in the protocol: there is no message that carries it, no endpoint that
// could request it, and no code path that writes it anywhere but the identity file. That is what
// makes "RetentionOps cannot impersonate your connector" a property of the design rather than a
// promise.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileName is the single file that carries a connector's identity.
const FileName = "identity.json"

// Identity is an enrolled connector.
type Identity struct {
	ConnectorID     string
	OrganizationID  string
	private         ed25519.PrivateKey
	controlPlaneKey ed25519.PublicKey
	EnrolledAt      time.Time
}

// stored is the on-disk form. The private key is a 32-byte seed rather than the expanded 64-byte
// value: the seed is the whole secret, and storing the smaller thing keeps the file unambiguous.
type stored struct {
	Version               int       `json:"version"`
	ConnectorID           string    `json:"connector_id"`
	OrganizationID        string    `json:"organization_id"`
	PrivateKeySeed        string    `json:"private_key_seed"`
	ControlPlanePublicKey string    `json:"control_plane_public_key"`
	EnrolledAt            time.Time `json:"enrolled_at"`
}

// Generate creates a fresh key pair. It is called exactly once per connector, before enrollment,
// and the public half is the only part that is ever transmitted.
func Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: generate key: %w", err)
	}
	return public, private, nil
}

// EncodePublic renders a public key the way the protocol carries it.
func EncodePublic(key ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(key)
}

// DecodePublic parses a protocol-encoded public key.
func DecodePublic(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("identity: public key is not base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("identity: public key is %d bytes, expected %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Save writes the identity file with owner-only permissions.
func Save(directory string, private ed25519.PrivateKey, response Enrollment) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("identity: create %s: %w", directory, err)
	}
	document := stored{
		Version:               1,
		ConnectorID:           response.ConnectorID,
		OrganizationID:        response.OrganizationID,
		PrivateKeySeed:        base64.StdEncoding.EncodeToString(private.Seed()),
		ControlPlanePublicKey: response.ControlPlanePublicKey,
		EnrolledAt:            response.IssuedAt,
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("identity: encode: %w", err)
	}
	path := filepath.Join(directory, FileName)
	// Written through a temporary file so an interrupted enrollment cannot leave a half-written
	// identity that the connector would then refuse to start with.
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return fmt.Errorf("identity: write %s: %w", temporary, err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("identity: install %s: %w", path, err)
	}
	return nil
}

// Enrollment is the part of an enrollment response that becomes durable identity.
type Enrollment struct {
	ConnectorID           string
	OrganizationID        string
	ControlPlanePublicKey string
	IssuedAt              time.Time
}

// Load reads an enrolled identity, refusing a file other users can read.
func Load(directory string) (*Identity, error) {
	path := filepath.Join(directory, FileName)
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("identity: %s: %w (run `retentionops-connector enroll` first)", path, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("identity: %s is mode %#o; the private key must not be readable by group or other", path, mode)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // path is derived from the operator's own configuration
	if err != nil {
		return nil, fmt.Errorf("identity: read %s: %w", path, err)
	}
	var document stored
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("identity: parse %s: %w", path, err)
	}
	if document.Version != 1 {
		return nil, fmt.Errorf("identity: %s has version %d, which this build does not understand", path, document.Version)
	}
	seed, err := base64.StdEncoding.DecodeString(document.PrivateKeySeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity: %s does not contain a usable private key", path)
	}
	controlPlaneKey, err := DecodePublic(document.ControlPlanePublicKey)
	if err != nil {
		return nil, fmt.Errorf("identity: %s: %w", path, err)
	}
	return &Identity{
		ConnectorID:     document.ConnectorID,
		OrganizationID:  document.OrganizationID,
		private:         ed25519.NewKeyFromSeed(seed),
		controlPlaneKey: controlPlaneKey,
		EnrolledAt:      document.EnrolledAt,
	}, nil
}

// Sign produces the protocol's signature form over payload.
func (i *Identity) Sign(payload []byte) (string, error) {
	if len(i.private) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("identity: no private key loaded")
	}
	return "ed25519:" + base64.StdEncoding.EncodeToString(ed25519.Sign(i.private, payload)), nil
}

// PublicKey is this connector's own public key, for display in `doctor` output.
func (i *Identity) PublicKey() ed25519.PublicKey {
	return i.private.Public().(ed25519.PublicKey)
}

// VerifyControlPlane checks a signature made by the control plane this connector enrolled with.
//
// The key was pinned at enrollment and is never refreshed from the network. A control plane that
// rotates its signing key has to re-enroll its connectors, which is deliberately a visible,
// customer-initiated operation: an attacker who can answer one HTTPS request must not be able to
// become the party this connector obeys.
func (i *Identity) VerifyControlPlane(payload []byte, signature string) error {
	return VerifySignature(i.controlPlaneKey, payload, signature)
}

// ControlPlaneKey is the pinned key, for display and for the doctor's fingerprint check.
func (i *Identity) ControlPlaneKey() ed25519.PublicKey { return i.controlPlaneKey }

// VerifySignature checks a protocol-form signature against a public key.
func VerifySignature(key ed25519.PublicKey, payload []byte, signature string) error {
	const prefix = "ed25519:"
	if len(signature) <= len(prefix) || signature[:len(prefix)] != prefix {
		return fmt.Errorf("identity: signature is not an ed25519 signature")
	}
	raw, err := base64.StdEncoding.DecodeString(signature[len(prefix):])
	if err != nil {
		return fmt.Errorf("identity: signature is not base64: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("identity: signature is %d bytes, expected %d", len(raw), ed25519.SignatureSize)
	}
	if !ed25519.Verify(key, payload, raw) {
		return fmt.Errorf("identity: signature does not verify")
	}
	return nil
}

// Fingerprint is a short, stable, human-comparable form of a public key, for the enrollment
// output and the doctor. An operator comparing what the console shows with what the connector
// pinned should not have to compare 44 base64 characters by eye.
func Fingerprint(key ed25519.PublicKey) string {
	encoded := base64.StdEncoding.EncodeToString(key)
	return encoded[:8] + "…" + encoded[len(encoded)-8:]
}
