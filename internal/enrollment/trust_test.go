package enrollment

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// "certificate signed by unknown authority" is accurate and useless: it names TLS, not the
// question in `init` whose answer fixes it. An operator hit this three times in one afternoon
// with the certificate already sitting in their home directory.
func TestATrustFailureNamesTheQuestionThatFixesIt(t *testing.T) {
	underlying := fmt.Errorf("post: %w", x509.UnknownAuthorityError{})

	without := explainTrust(underlying, "")
	if !strings.Contains(without.Error(), "run init again and supply its CA") {
		t.Fatalf("no remedy: %v", without)
	}
	if !errors.Is(without, underlying) {
		t.Fatal("the original error was lost")
	}

	// A bundle that carries a certificate which does not sign this one is a different mistake,
	// and telling that operator to supply a CA they already supplied would send them in a circle.
	with := explainTrust(underlying, "/etc/retentionops/certs/control-plane-ca.pem")
	if !strings.Contains(with.Error(), "does not sign it") {
		t.Fatalf("the carried certificate was not named: %v", with)
	}
}

func TestAnUnrelatedFailureIsLeftAlone(t *testing.T) {
	underlying := errors.New("connection refused")
	if explained := explainTrust(underlying, ""); explained != underlying {
		t.Fatalf("a non-TLS failure was rewritten: %v", explained)
	}
}
