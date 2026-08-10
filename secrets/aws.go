package secrets

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// AWSSecretsManagerProvider reads a secret from AWS Secrets Manager.
//
// It speaks the API directly rather than pulling in the AWS SDK. The connector runs with delete
// rights on a customer's production database, so every dependency it carries is a dependency the
// customer's security team inherits — and the SDK is a very large inheritance for one call. What
// is implemented here is one operation, GetSecretValue, and the SigV4 signature it needs.
type AWSSecretsManagerProvider struct {
	region string
	client *http.Client
}

// NewAWSSecretsManagerProvider builds the provider. An empty region defers to AWS_REGION,
// AWS_DEFAULT_REGION, or the region embedded in an ARN reference.
func NewAWSSecretsManagerProvider(region string) *AWSSecretsManagerProvider {
	return &AWSSecretsManagerProvider{
		region: region,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Name implements Provider.
func (p *AWSSecretsManagerProvider) Name() string { return "aws-secrets-manager" }

// Resolve implements Provider.
//
// A reference may be a secret name or ARN, optionally followed by "#key" to select one member of
// a JSON secret — the shape Secrets Manager itself encourages for database credentials.
func (p *AWSSecretsManagerProvider) Resolve(ctx context.Context, ref string) ([]byte, error) {
	secretID, member, _ := strings.Cut(ref, "#")
	region, err := p.resolveRegion(secretID)
	if err != nil {
		return nil, err
	}
	credentials, err := resolveAWSCredentials(ctx, p.client)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{"SecretId": secretID})
	if err != nil {
		return nil, fmt.Errorf("secrets: encode request: %w", err)
	}
	host := "secretsmanager." + region + ".amazonaws.com"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("secrets: build request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-amz-json-1.1")
	request.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	request.Host = host
	signV4(request, body, credentials, region, "secretsmanager", time.Now().UTC())

	response, err := p.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("secrets: call Secrets Manager: %w", err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("secrets: read Secrets Manager response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		// The status and the AWS error type are safe to surface; the body is not echoed, because
		// an error document from a misaddressed call can quote the request.
		return nil, fmt.Errorf("secrets: Secrets Manager refused GetSecretValue for %q: HTTP %d (%s)",
			secretID, response.StatusCode, response.Header.Get("X-Amzn-Errortype"))
	}
	return extractSecret(payload, member)
}

func (p *AWSSecretsManagerProvider) resolveRegion(secretID string) (string, error) {
	if p.region != "" {
		return p.region, nil
	}
	// arn:aws:secretsmanager:<region>:<account>:secret:<name>
	if parts := strings.Split(secretID, ":"); len(parts) > 3 && parts[0] == "arn" {
		return parts[3], nil
	}
	for _, variable := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if region := os.Getenv(variable); region != "" {
			return region, nil
		}
	}
	return "", fmt.Errorf("secrets: no AWS region: set AWS_REGION or use a full secret ARN")
}

type secretValue struct {
	SecretString string `json:"SecretString"`
	SecretBinary string `json:"SecretBinary"`
}

func extractSecret(payload []byte, member string) ([]byte, error) {
	var value secretValue
	if err := json.Unmarshal(payload, &value); err != nil {
		return nil, fmt.Errorf("secrets: Secrets Manager response is not JSON: %w", err)
	}
	if value.SecretString == "" && value.SecretBinary != "" {
		raw, err := base64.StdEncoding.DecodeString(value.SecretBinary)
		if err != nil {
			return nil, fmt.Errorf("secrets: SecretBinary is not base64: %w", err)
		}
		return raw, nil
	}
	if member == "" {
		return []byte(value.SecretString), nil
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(value.SecretString), &document); err != nil {
		return nil, fmt.Errorf("secrets: secret is not a JSON document, so #%s cannot be selected", member)
	}
	selected, ok := document[member].(string)
	if !ok {
		return nil, fmt.Errorf("secrets: secret has no string member %q", member)
	}
	return []byte(selected), nil
}

type awsCredentials struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"Token"`
}

// resolveAWSCredentials walks the credential sources a connector realistically runs under:
// explicit environment variables, an ECS/EKS task-role endpoint, then EC2 instance metadata.
//
// Web-identity (IRSA) is not implemented in this build. On EKS, mount the credential as a file
// and use the "file" provider, or project the token yourself; see docs/security.md.
func resolveAWSCredentials(ctx context.Context, client *http.Client) (awsCredentials, error) {
	if key, secret := os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"); key != "" && secret != "" {
		return awsCredentials{
			AccessKeyID:     key,
			SecretAccessKey: secret,
			SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
		}, nil
	}
	if url := containerCredentialsURL(); url != "" {
		return fetchCredentials(ctx, client, url, http.Header{
			"Authorization": []string{os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")},
		})
	}
	return instanceCredentials(ctx, client)
}

func containerCredentialsURL() string {
	if full := os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"); full != "" {
		return full
	}
	if relative := os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"); relative != "" {
		return "http://169.254.170.2" + relative
	}
	return ""
}

func fetchCredentials(ctx context.Context, client *http.Client, url string, header http.Header) (awsCredentials, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return awsCredentials{}, fmt.Errorf("secrets: build credential request: %w", err)
	}
	for name, values := range header {
		if len(values) > 0 && values[0] != "" {
			request.Header.Set(name, values[0])
		}
	}
	response, err := client.Do(request)
	if err != nil {
		return awsCredentials{}, fmt.Errorf("secrets: fetch AWS credentials: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return awsCredentials{}, fmt.Errorf("secrets: AWS credential endpoint answered HTTP %d", response.StatusCode)
	}
	var credentials awsCredentials
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<16)).Decode(&credentials); err != nil {
		return awsCredentials{}, fmt.Errorf("secrets: parse AWS credentials: %w", err)
	}
	if credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" {
		return awsCredentials{}, fmt.Errorf("secrets: AWS credential endpoint returned no usable credentials")
	}
	return credentials, nil
}

// instanceCredentials uses IMDSv2 only. IMDSv1 is not attempted, because a connector that will
// happily read unauthenticated instance metadata is a connector that turns any SSRF in the same
// host into a credential leak.
func instanceCredentials(ctx context.Context, client *http.Client) (awsCredentials, error) {
	const base = "http://169.254.169.254"
	tokenRequest, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/latest/api/token", nil)
	if err != nil {
		return awsCredentials{}, fmt.Errorf("secrets: build IMDS token request: %w", err)
	}
	tokenRequest.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "300")
	tokenResponse, err := client.Do(tokenRequest)
	if err != nil {
		return awsCredentials{}, fmt.Errorf("secrets: no AWS credentials available (env, container endpoint and IMDSv2 all failed): %w", err)
	}
	defer tokenResponse.Body.Close()
	if tokenResponse.StatusCode != http.StatusOK {
		return awsCredentials{}, fmt.Errorf("secrets: IMDSv2 answered HTTP %d", tokenResponse.StatusCode)
	}
	token, err := io.ReadAll(io.LimitReader(tokenResponse.Body, 4096))
	if err != nil {
		return awsCredentials{}, fmt.Errorf("secrets: read IMDSv2 token: %w", err)
	}
	header := http.Header{"X-aws-ec2-metadata-token": []string{string(token)}}

	roleRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/latest/meta-data/iam/security-credentials/", nil)
	if err != nil {
		return awsCredentials{}, fmt.Errorf("secrets: build IMDS role request: %w", err)
	}
	roleRequest.Header = header.Clone()
	roleResponse, err := client.Do(roleRequest)
	if err != nil {
		return awsCredentials{}, fmt.Errorf("secrets: list instance roles: %w", err)
	}
	defer roleResponse.Body.Close()
	if roleResponse.StatusCode != http.StatusOK {
		return awsCredentials{}, fmt.Errorf("secrets: instance has no attached role (HTTP %d)", roleResponse.StatusCode)
	}
	role, err := io.ReadAll(io.LimitReader(roleResponse.Body, 4096))
	if err != nil {
		return awsCredentials{}, fmt.Errorf("secrets: read instance role: %w", err)
	}
	name := strings.TrimSpace(string(role))
	if index := strings.IndexByte(name, '\n'); index >= 0 {
		name = name[:index]
	}
	return fetchCredentials(ctx, client, base+"/latest/meta-data/iam/security-credentials/"+name, header)
}

// signV4 applies AWS Signature Version 4 to request.
func signV4(request *http.Request, body []byte, credentials awsCredentials, region, service string, now time.Time) {
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	request.Header.Set("X-Amz-Date", amzDate)
	if credentials.SessionToken != "" {
		request.Header.Set("X-Amz-Security-Token", credentials.SessionToken)
	}

	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if credentials.SessionToken != "" {
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)

	var canonicalHeaders strings.Builder
	for _, name := range signed {
		value := request.Header.Get(name)
		if name == "host" {
			value = request.Host
		}
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(value))
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(signed, ";")
	payloadHash := hex.EncodeToString(sha256Sum(body))

	canonicalRequest := strings.Join([]string{
		request.Method,
		"/",
		"",
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hex.EncodeToString(sha256Sum([]byte(canonicalRequest))),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+credentials.SecretAccessKey), dateStamp)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	request.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		credentials.AccessKeyID, scope, signedHeaders, signature))
}

func sha256Sum(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}
