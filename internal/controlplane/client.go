// Package controlplane is the connector's only outbound conversation.
//
// Every call in this package is initiated by the connector, over HTTPS, to one configured host.
// The connector opens no listening socket for RetentionOps, so a customer's firewall needs no
// inbound rule, no port forward and no exception — which is the single most common reason an
// agent like this never gets deployed at all.
package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"crypto/tls"

	"github.com/solutions-optigm/retentionops-connector/internal/identity"
	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
)

// ErrNoWork is returned when a long poll ends with nothing to do.
var ErrNoWork = errors.New("controlplane: no work")

const (
	maxResponseBytes = 1 << 20
	userAgent        = "retentionops-connector/"
)

// Client talks to one control plane.
type Client struct {
	baseURL  string
	http     *http.Client
	identity *identity.Identity
	version  string
}

// New builds a client. An identity of nil is valid only for enrollment, which is the one call
// made before the connector has one.
func New(baseURL, caFile, version string, id *identity.Identity, timeout time.Duration) (*Client, error) {
	httpClient, err := newHTTPClient(caFile, timeout)
	if err != nil {
		return nil, err
	}
	return &Client{
		baseURL:  baseURL,
		http:     httpClient,
		identity: id,
		version:  version,
	}, nil
}

func newHTTPClient(caFile string, timeout time.Duration) (*http.Client, error) {
	transport := &http.Transport{
		// The connector never needs many connections to one host, and an idle pool that outlives
		// a network change is a source of confusing failures on customer networks.
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if caFile != "" {
		pool, err := loadCertPool(caFile)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: transport, Timeout: timeout}, nil
}

// Probe proves that the configured control-plane TLS path can complete a handshake. It stops at
// the first HTTP response because redirects belong to the browser surface, not connector health.
func Probe(ctx context.Context, baseURL, caFile string, timeout time.Duration) (int, error) {
	client, err := newHTTPClient(caFile, timeout)
	if err != nil {
		return 0, err
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, baseURL, nil)
	if err != nil {
		return 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return response.StatusCode, nil
}

func loadCertPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("controlplane: read %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("controlplane: %s contains no usable certificate", caFile)
	}
	return pool, nil
}

// Enroll exchanges a single-use token for a connector identity.
//
// This is the only unsigned call in the protocol, because it is the call that establishes the
// key everything else is signed with. The private key was already generated locally and is not
// part of the request.
func (c *Client) Enroll(ctx context.Context, request protocolv1.EnrollmentRequest) (*protocolv1.EnrollmentResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("controlplane: encode enrollment: %w", err)
	}
	raw, err := c.do(ctx, http.MethodPost, "/connector/v1/enroll", body, false)
	if err != nil {
		return nil, err
	}
	var response protocolv1.EnrollmentResponse
	if err := protocolv1.DecodeStrict(raw, &response); err != nil {
		return nil, err
	}
	if response.ProtocolVersion != protocolv1.Version {
		return nil, fmt.Errorf("controlplane: control plane speaks protocol %q, this connector speaks %q",
			response.ProtocolVersion, protocolv1.Version)
	}
	if _, err := identity.DecodePublic(response.ControlPlanePublicKey); err != nil {
		return nil, err
	}
	return &response, nil
}

// NextJob long-polls for work.
//
// The control plane holds the request open for up to wait seconds and answers 204 when there is
// nothing to do. That keeps dispatch latency near zero without a persistent connection, and it
// survives NAT, forward proxies and corporate middleboxes that would drop an idle socket or a
// WebSocket upgrade.
func (c *Client) NextJob(ctx context.Context, wait time.Duration) ([]byte, error) {
	path := "/connector/v1/jobs/next?wait=" + strconv.Itoa(int(wait.Seconds()))
	raw, err := c.do(ctx, http.MethodGet, path, nil, true)
	if errors.Is(err, ErrNoWork) {
		return nil, ErrNoWork
	}
	return raw, err
}

// Acknowledge tells the control plane the job was received and verified.
func (c *Client) Acknowledge(ctx context.Context, jobID string) error {
	_, err := c.do(ctx, http.MethodPost, "/connector/v1/jobs/"+jobID+"/ack", []byte("{}"), true)
	return acceptNoContent(err)
}

// Event delivers one progress record.
func (c *Client) Event(ctx context.Context, event protocolv1.JobEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("controlplane: encode event: %w", err)
	}
	_, err = c.do(ctx, http.MethodPost, "/connector/v1/jobs/"+event.JobID+"/events", body, true)
	return acceptNoContent(err)
}

// Control asks whether the next destructive batch may begin.
//
// The random query challenge is echoed inside the signed answer. A valid but older RUN answer
// therefore cannot be replayed after an operator has requested PAUSE or CANCEL.
func (c *Client) Control(ctx context.Context, jobID string) (*protocolv1.ExecutionControl, error) {
	challenge, err := newNonce()
	if err != nil {
		return nil, err
	}
	path := "/connector/v1/jobs/" + jobID + "/control?request_nonce=" + url.QueryEscape(challenge)
	raw, err := c.do(ctx, http.MethodGet, path, nil, true)
	if err != nil {
		return nil, err
	}
	control, err := protocolv1.DecodeControl(raw)
	if err != nil {
		return nil, err
	}
	if err := control.Validate(
		jobID, c.identity.OrganizationID, c.identity.ConnectorID, challenge,
	); err != nil {
		return nil, err
	}
	now := time.Now()
	if !now.Before(control.ExpiresAt) || control.IssuedAt.After(now.Add(2*time.Minute)) {
		return nil, errors.New("controlplane: execution control is outside its validity window")
	}
	canonical, err := protocolv1.CanonicalizeRawWithout(raw, "signature")
	if err != nil {
		return nil, err
	}
	if err := c.identity.VerifyControlPlane(
		protocolv1.SigningPayload(protocolv1.ControlDomain, canonical), control.Signature,
	); err != nil {
		return nil, fmt.Errorf("controlplane: execution control signature is invalid: %w", err)
	}
	return control, nil
}

// Complete delivers the signed result.
func (c *Client) Complete(ctx context.Context, result protocolv1.JobResult) error {
	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("controlplane: encode result: %w", err)
	}
	_, err = c.do(ctx, http.MethodPost, "/connector/v1/jobs/"+result.JobID+"/complete", body, true)
	return err
}

// Heartbeat reports liveness and the connector's self-declared shape.
func (c *Client) Heartbeat(ctx context.Context, heartbeat protocolv1.Heartbeat) error {
	body, err := json.Marshal(heartbeat)
	if err != nil {
		return fmt.Errorf("controlplane: encode heartbeat: %w", err)
	}
	_, err = c.do(ctx, http.MethodPost, "/connector/v1/heartbeat", body, true)
	return acceptNoContent(err)
}

func acceptNoContent(err error) error {
	if errors.Is(err, ErrNoWork) {
		return nil
	}
	return err
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, signed bool) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("controlplane: build request: %w", err)
	}
	request.Header.Set("User-Agent", userAgent+c.version)
	request.Header.Set("Accept", "application/json")
	request.Header.Set(protocolv1.HeaderVersion, protocolv1.Version)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if signed {
		if err := c.sign(request, method, path, body); err != nil {
			return nil, err
		}
	}

	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("controlplane: %s %s: %w", method, path, err)
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusNoContent:
		return nil, ErrNoWork
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
	default:
		return nil, fmt.Errorf("controlplane: %s %s answered HTTP %d", method, path, response.StatusCode)
	}
	// Bounded read: a control plane that has been replaced by something hostile must not be able
	// to exhaust this process's memory with an unbounded body.
	return io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
}

func (c *Client) sign(request *http.Request, method, path string, body []byte) error {
	if c.identity == nil {
		return errors.New("controlplane: this call requires an enrolled identity")
	}
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	signature, err := c.identity.Sign(protocolv1.RequestSigningPayload(method, path, timestamp, nonce, body))
	if err != nil {
		return err
	}
	request.Header.Set(protocolv1.HeaderConnector, c.identity.ConnectorID)
	request.Header.Set(protocolv1.HeaderOrganization, c.identity.OrganizationID)
	request.Header.Set(protocolv1.HeaderTimestamp, timestamp)
	request.Header.Set(protocolv1.HeaderNonce, nonce)
	request.Header.Set(protocolv1.HeaderSignature, signature)
	return nil
}

func newNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("controlplane: generate nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
