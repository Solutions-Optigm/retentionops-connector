package debpack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestWriteProducesDeterministicDebianArchive(t *testing.T) {
	pack := Package{
		Control: []Entry{{Name: "control", Mode: 0o644, Data: []byte("Package: retentionops-connector\n")}},
		Data:    []Entry{{Name: "usr/bin/retentionops-connector", Mode: 0o755, Data: []byte("binary")}},
	}
	first := filepath.Join(t.TempDir(), "first.deb")
	second := filepath.Join(t.TempDir(), "second.deb")
	if err := Write(first, pack); err != nil {
		t.Fatal(err)
	}
	if err := Write(second, pack); err != nil {
		t.Fatal(err)
	}
	left, err := os.ReadFile(first) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatal(err)
	}
	right, err := os.ReadFile(second) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Fatal("identical package inputs produced different bytes")
	}
	if got := arMemberNames(t, left); strings.Join(got, ",") != "debian-binary,control.tar.gz,data.tar.gz" {
		t.Fatalf("unexpected ar members: %v", got)
	}
	data, err := tarGzip(pack.Data)
	if err != nil {
		t.Fatal(err)
	}
	if got := tarNames(t, data); strings.Join(got, ",") != "usr/,usr/bin/,usr/bin/retentionops-connector" {
		t.Fatalf("package omits required parent directories: %v", got)
	}
}

func arMemberNames(t *testing.T, raw []byte) []string {
	t.Helper()
	if !bytes.HasPrefix(raw, []byte("!<arch>\n")) {
		t.Fatal("missing ar signature")
	}
	var names []string
	for offset := 8; offset < len(raw); {
		if offset+60 > len(raw) {
			t.Fatal("truncated ar header")
		}
		header := raw[offset : offset+60]
		name := strings.TrimSuffix(strings.TrimSpace(string(header[:16])), "/")
		size, err := strconv.Atoi(strings.TrimSpace(string(header[48:58])))
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
		offset += 60 + size
		if size%2 != 0 {
			offset++
		}
	}
	return names
}

func tarNames(t *testing.T, raw []byte) []string {
	t.Helper()
	zipper, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(zipper)
	var names []string
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
	}
	return names
}
