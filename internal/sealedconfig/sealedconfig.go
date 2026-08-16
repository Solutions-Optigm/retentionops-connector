// Package sealedconfig opens a source configuration a console sealed to this connector.
//
// The control plane relays these envelopes and holds no key that opens one (ADR-034). What
// crosses is the *shape* of a connection — where to connect, as which roles, under which TLS
// mode. No password is ever sealed: a stored ciphertext is readable retroactively by anyone who
// obtains the key later, and the claim worth keeping is that no database secret transits
// RetentionOps at all.
//
// Nothing in this package puts plaintext, key material or a shared secret into an error. An
// error says which check failed and nothing about what was being checked, because these errors
// travel into logs the control plane can eventually read.
package sealedconfig

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Version is the only envelope version this connector opens. A second version is a protocol
// change with its own review, not a field somebody widens.
const Version = 1

// domain separates this key derivation and this AAD from every other use of the same primitives.
const domain = "retentionops/sealed-config/v1"

// MaxCiphertextBytes caps what will be base64-decoded and handed to AES-GCM. A configuration is a
// few hundred bytes; the ceiling exists so an oversized envelope is refused by a length check
// rather than by allocating whatever the control plane relayed.
const MaxCiphertextBytes = 16 * 1024

// ClockSkew is how far the two clocks may disagree before a valid envelope is refused. Sealing
// happens in a browser on somebody's laptop, so the drift is theirs, not the operator's.
const ClockSkew = 5 * time.Minute

var (
	// ErrWrongRecipient covers every authentication failure alike: a foreign recipient, a
	// tampered field and a corrupted ciphertext are indistinguishable to AES-GCM, and inventing
	// a distinction here would be inventing information.
	ErrWrongRecipient = errors.New("sealedconfig: envelope does not open with this connector's key")
	ErrExpired        = errors.New("sealedconfig: envelope has expired")
	ErrNotYetValid    = errors.New("sealedconfig: envelope is not valid yet")
	ErrTooLarge       = errors.New("sealedconfig: envelope exceeds the accepted size")
	ErrVersion        = errors.New("sealedconfig: unsupported envelope version")
	ErrMalformed      = errors.New("sealedconfig: envelope is malformed")
)

// Envelope is the relayed document. Every field outside the ciphertext is authenticated by the
// AAD, so the control plane cannot alter one without the connector noticing.
type Envelope struct {
	Version        int    `json:"version"`
	EnvelopeID     string `json:"envelope_id"`
	OrganizationID string `json:"organization_id"`
	SourceID       string `json:"source_id"`
	ConnectorID    string `json:"connector_id"`
	IssuedAt       string `json:"issued_at"`
	EphemeralKey   string `json:"ephemeral_key"`
	ExpiresAt      string `json:"expires_at"`
	Nonce          string `json:"nonce"`
	Ciphertext     string `json:"ciphertext"`
}

// SourceConfiguration is the sealed payload: where to connect and as whom, never a secret.
type SourceConfiguration struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	Database       string   `json:"database"`
	ReaderRole     string   `json:"reader_role"`
	ExecutorRole   string   `json:"executor_role,omitempty"`
	TLSMode        string   `json:"tls_mode"`
	AllowedSchemas []string `json:"allowed_schemas,omitempty"`
}

// AdditionalData builds the authenticated associated data.
//
// Length-prefixed concatenation rather than JSON. Two JSON encoders agree on a document's meaning
// and not on its bytes — key order, escaping and integer formatting all vary — and AES-GCM
// authenticates bytes. A mismatch would surface as "does not open with this connector's key",
// which points at the wrong thing entirely. Each field is a 16-bit big-endian length followed by
// its UTF-8 bytes, in this fixed order, so no separator can be smuggled inside a value.
func AdditionalData(envelope Envelope) []byte {
	fields := []string{
		domain,
		fmt.Sprintf("%d", envelope.Version),
		envelope.EnvelopeID,
		envelope.OrganizationID,
		envelope.SourceID,
		envelope.ConnectorID,
		envelope.IssuedAt,
		envelope.ExpiresAt,
	}
	size := 0
	for _, field := range fields {
		size += 2 + len(field)
	}
	out := make([]byte, 0, size)
	for _, field := range fields {
		out = binary.BigEndian.AppendUint16(out, uint16(len(field)))
		out = append(out, field...)
	}
	return out
}

// deriveKey turns one ECDH agreement into one AES key.
//
// Both public keys go into the salt so the derived key is bound to this exact pair. Without that,
// a shared secret reused against a different recipient would derive the same key.
func deriveKey(shared, ephemeral, recipient []byte) ([]byte, error) {
	salt := make([]byte, 0, len(ephemeral)+len(recipient))
	salt = append(salt, ephemeral...)
	salt = append(salt, recipient...)
	key, err := hkdf.Key(sha256.New, shared, salt, domain, 32)
	if err != nil {
		return nil, ErrMalformed
	}
	return key, nil
}

// Open authenticates and decrypts an envelope addressed to this connector.
//
// The caller supplies the identity it expects the envelope to name. Checking that here rather
// than trusting the document is what stops an envelope sealed for one connector from being
// applied by another that happens to receive it.
func Open(envelope Envelope, recipient *ecdh.PrivateKey, connectorID, organizationID string, now time.Time) (SourceConfiguration, error) {
	var empty SourceConfiguration
	if envelope.Version != Version {
		return empty, ErrVersion
	}
	if envelope.ConnectorID != connectorID || envelope.OrganizationID != organizationID {
		return empty, ErrWrongRecipient
	}
	issuedAt, err := time.Parse(time.RFC3339, envelope.IssuedAt)
	if err != nil {
		return empty, ErrMalformed
	}
	expiresAt, err := time.Parse(time.RFC3339, envelope.ExpiresAt)
	if err != nil {
		return empty, ErrMalformed
	}
	if now.After(expiresAt.Add(ClockSkew)) {
		return empty, ErrExpired
	}
	if issuedAt.After(now.Add(ClockSkew)) {
		return empty, ErrNotYetValid
	}

	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return empty, ErrMalformed
	}
	// Checked after decoding as well as before use: base64 inflates by a third, so the encoded
	// bound is not the bound that matters.
	if len(ciphertext) > MaxCiphertextBytes {
		return empty, ErrTooLarge
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != 12 {
		return empty, ErrMalformed
	}
	ephemeralRaw, err := base64.StdEncoding.DecodeString(envelope.EphemeralKey)
	if err != nil {
		return empty, ErrMalformed
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(ephemeralRaw)
	if err != nil {
		return empty, ErrMalformed
	}

	shared, err := recipient.ECDH(ephemeral)
	if err != nil {
		return empty, ErrWrongRecipient
	}
	key, err := deriveKey(shared, ephemeral.Bytes(), recipient.PublicKey().Bytes())
	if err != nil {
		return empty, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return empty, ErrMalformed
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return empty, ErrMalformed
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, AdditionalData(envelope))
	if err != nil {
		return empty, ErrWrongRecipient
	}

	var configuration SourceConfiguration
	if err := json.Unmarshal(plaintext, &configuration); err != nil {
		return empty, ErrMalformed
	}
	return configuration, nil
}

// Seal produces an envelope the way a console does.
//
// Shipped rather than kept in the test tree so the cross-language vectors exercise the same code
// the connector opens with. A connector never calls it in production; nothing reaches it from the
// agent, and it holds no authority of its own.
func Seal(configuration SourceConfiguration, recipient *ecdh.PublicKey, envelope Envelope) (Envelope, error) {
	plaintext, err := json.Marshal(configuration)
	if err != nil {
		return Envelope{}, ErrMalformed
	}
	// A fresh ephemeral key per envelope. Reusing one would derive the same AES key for every
	// envelope to the same connector, and a repeated (key, nonce) pair in GCM loses both
	// confidentiality and authenticity.
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Envelope{}, ErrMalformed
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return Envelope{}, ErrMalformed
	}
	key, err := deriveKey(shared, ephemeral.PublicKey().Bytes(), recipient.Bytes())
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, ErrMalformed
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Envelope{}, ErrMalformed
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, ErrMalformed
	}

	envelope.Version = Version
	envelope.EphemeralKey = base64.StdEncoding.EncodeToString(ephemeral.PublicKey().Bytes())
	envelope.Nonce = base64.StdEncoding.EncodeToString(nonce)
	envelope.Ciphertext = base64.StdEncoding.EncodeToString(
		aead.Seal(nil, nonce, plaintext, AdditionalData(envelope)),
	)
	return envelope, nil
}
