package secrets

import (
	"context"
	"strings"
	"testing"
)

type emptyProvider struct{}

func (emptyProvider) Name() string { return "empty" }

func (emptyProvider) Resolve(context.Context, string) ([]byte, error) { return nil, nil }

func TestRegistryRejectsAnEmptySecret(t *testing.T) {
	_, err := NewRegistry(emptyProvider{}).Resolve(context.Background(), "empty", "reader-password")
	if err == nil || !strings.Contains(err.Error(), "empty value") {
		t.Fatalf("empty secret was accepted: %v", err)
	}
}
