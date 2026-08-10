// Package protocolv1 is the wire contract between a RetentionOps control plane and a
// RetentionOps connector.
//
// It is deliberately the only package in this module that a third party has to read in order to
// know everything the control plane can ask for. The operation set is closed, every payload is
// declarative, and no type here has a member that could carry SQL, a shell command, a file path
// or a credential.
package protocolv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Version is the only protocol version this module implements. A connector refuses anything
// else rather than guessing: forward compatibility is obtained by shipping a new connector.
const Version = "1"

// Signing domains. Prefixing the signed bytes keeps a job signature from ever being accepted as
// an evidence signature, even though both are produced by Ed25519 over canonical JSON.
const (
	JobDomain      = "RetentionOps-Job-v1"
	EvidenceDomain = "RetentionOps-Evidence-v1"
	// ControlDomain covers the short-lived RUN/PAUSE/CANCEL answer returned at a destructive
	// checkpoint. It is distinct from JobDomain because controls never rewrite or replace the
	// immutable instruction a human approved.
	ControlDomain = "RetentionOps-Control-v1"
	// RequestDomain covers a connector's own HTTP calls to the control plane. Every request is
	// signed individually rather than authenticated with a bearer token: there is then no
	// credential in flight that a proxy, a log or a memory dump could yield and replay.
	RequestDomain = "RetentionOps-Request-v1"
)

// Connector-facing HTTP headers. Named here so the two implementations of this protocol cannot
// drift on a string.
const (
	HeaderConnector    = "X-RetentionOps-Connector"
	HeaderOrganization = "X-RetentionOps-Organization"
	HeaderTimestamp    = "X-RetentionOps-Timestamp"
	HeaderNonce        = "X-RetentionOps-Nonce"
	HeaderSignature    = "X-RetentionOps-Signature"
	HeaderVersion      = "X-RetentionOps-Protocol"
)

// RequestSigningPayload is the exact byte string a connector signs for one HTTP call.
//
// Method and path are covered so a signature captured from a read cannot be replayed onto a
// write. The body digest is covered so the body cannot be swapped. The timestamp and nonce make
// the whole thing single-use inside a short window.
func RequestSigningPayload(method, path, timestamp, nonce string, body []byte) []byte {
	fields := strings.Join([]string{method, path, timestamp, nonce, Digest(body)}, "\n")
	return SigningPayload(RequestDomain, []byte(fields))
}

// Canonicalize renders v in the RFC 8785 canonical form, restricted to the value space this
// protocol actually uses: objects, arrays, strings, booleans, null and integers.
//
// Floating-point numbers are refused rather than serialized. RFC 8785 defines a canonical form
// for them, but making a Go and a Python implementation agree bit-for-bit on every double is a
// far larger commitment than a retention protocol needs — and a digest that disagrees across
// implementations is a signature that fails in production, not in a test. The schemas therefore
// declare every numeric member as an integer, and this function enforces it.
func Canonicalize(v any) ([]byte, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("protocol: encode: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var tree any
	if err := decoder.Decode(&tree); err != nil {
		return nil, fmt.Errorf("protocol: decode: %w", err)
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, tree); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// CanonicalizeWithout is Canonicalize with named top-level members removed. A signature covers
// the document minus the member that carries the signature itself.
func CanonicalizeWithout(v any, omit ...string) ([]byte, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("protocol: encode: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var tree map[string]any
	if err := decoder.Decode(&tree); err != nil {
		return nil, fmt.Errorf("protocol: decode: %w", err)
	}
	for _, key := range omit {
		delete(tree, key)
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, tree); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// CanonicalizeRawWithout canonicalizes bytes that arrived over the network, minus the named
// top-level members.
//
// It works from the received bytes rather than from a decoded struct because that is the only
// way a signature check means what it claims to. Re-encoding a parsed document and hoping it
// reproduces the signer's bytes is how signature verification quietly degrades into a formality.
func CanonicalizeRawWithout(raw []byte, omit ...string) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var tree map[string]any
	if err := decoder.Decode(&tree); err != nil {
		return nil, fmt.Errorf("protocol: decode: %w", err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("protocol: trailing content")
	}
	for _, key := range omit {
		delete(tree, key)
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, tree); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Digest is the "sha256:<hex>" form used everywhere in this protocol.
func Digest(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// DigestOf canonicalizes v, minus the named members, and returns its digest.
func DigestOf(v any, omit ...string) (string, error) {
	canonical, err := CanonicalizeWithout(v, omit...)
	if err != nil {
		return "", err
	}
	return Digest(canonical), nil
}

// SigningPayload is what actually goes through Ed25519: a domain label, a newline, then the
// bytes being attested.
func SigningPayload(domain string, body []byte) []byte {
	payload := make([]byte, 0, len(domain)+1+len(body))
	payload = append(payload, domain...)
	payload = append(payload, '\n')
	return append(payload, body...)
}

func writeCanonical(out *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(typed))
	case string:
		writeCanonicalString(out, typed)
	case json.Number:
		return writeCanonicalNumber(out, typed)
	case []any:
		out.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		out.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				out.WriteByte(',')
			}
			writeCanonicalString(out, key)
			out.WriteByte(':')
			if err := writeCanonical(out, typed[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("protocol: unsupported canonical type %T", value)
	}
	return nil
}

func writeCanonicalNumber(out *bytes.Buffer, number json.Number) error {
	text := number.String()
	if strings.ContainsAny(text, ".eE") {
		return fmt.Errorf("protocol: %q is not an integer; this protocol carries no floats", text)
	}
	integer, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return fmt.Errorf("protocol: %q is not a signed 64-bit integer: %w", text, err)
	}
	out.WriteString(strconv.FormatInt(integer, 10))
	return nil
}

// writeCanonicalString applies the escaping RFC 8785 inherits from ECMAScript JSON.stringify:
// the two mandatory escapes, the six short forms, and \u00xx for every other control character.
// Everything else, including non-ASCII, is emitted literally as UTF-8.
func writeCanonicalString(out *bytes.Buffer, value string) {
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
				continue
			}
			out.WriteRune(r)
		}
	}
	out.WriteByte('"')
}

// lessUTF16 orders object members the way RFC 8785 requires: by UTF-16 code unit, not by byte.
// Every member name in this protocol is ASCII, where the two orders coincide — the general
// implementation is here so that stays a property of the data rather than an assumption in the
// code.
func lessUTF16(left, right string) bool {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	for index := 0; index < len(leftUnits) && index < len(rightUnits); index++ {
		if leftUnits[index] != rightUnits[index] {
			return leftUnits[index] < rightUnits[index]
		}
	}
	return len(leftUnits) < len(rightUnits)
}
