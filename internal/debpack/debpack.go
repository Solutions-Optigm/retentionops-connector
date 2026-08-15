// Package debpack writes the small, standard ar/tar container used by Debian packages.
package debpack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Entry struct {
	Name string
	Mode int64
	Data []byte
}

type Package struct {
	Control []Entry
	Data    []Entry
}

func Write(path string, pack Package) error {
	control, err := tarGzip(pack.Control)
	if err != nil {
		return err
	}
	data, err := tarGzip(pack.Data)
	if err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString("!<arch>\n"); err != nil {
		return err
	}
	for _, member := range []struct {
		name string
		data []byte
	}{{"debian-binary", []byte("2.0\n")}, {"control.tar.gz", control}, {"data.tar.gz", data}} {
		if err := writeArMember(file, member.name, member.data); err != nil {
			return err
		}
	}
	return file.Sync()
}

func ReadEntry(path, name string, mode int64) (Entry, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // packaging input selected by the release build
	if err != nil {
		return Entry{}, err
	}
	return Entry{Name: name, Mode: mode, Data: raw}, nil
}

func TemplateEntry(path, name string, mode int64, replacements map[string]string) (Entry, error) {
	entry, err := ReadEntry(path, name, mode)
	if err != nil {
		return Entry{}, err
	}
	text := string(entry.Data)
	for before, after := range replacements {
		text = strings.ReplaceAll(text, before, after)
	}
	entry.Data = []byte(text)
	return entry, nil
}

func tarGzip(entries []Entry) ([]byte, error) {
	ordered := append([]Entry(nil), entries...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].Name < ordered[right].Name })
	directorySet := map[string]struct{}{}
	for _, entry := range ordered {
		for directory := filepath.Dir(entry.Name); directory != "."; directory = filepath.Dir(directory) {
			directorySet[directory] = struct{}{}
		}
	}
	directories := make([]string, 0, len(directorySet))
	for directory := range directorySet {
		directories = append(directories, directory)
	}
	sort.Strings(directories)
	var buffer bytes.Buffer
	zipper, err := gzip.NewWriterLevel(&buffer, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	zipper.Header.ModTime = time.Unix(0, 0).UTC()
	writer := tar.NewWriter(zipper)
	for _, directory := range directories {
		header := &tar.Header{
			Name: directory + "/", Mode: 0o755, Uid: 0, Gid: 0, Uname: "root", Gname: "root",
			ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeDir, Format: tar.FormatUSTAR,
		}
		if err := writer.WriteHeader(header); err != nil {
			return nil, err
		}
	}
	for _, entry := range ordered {
		header := &tar.Header{
			Name: entry.Name, Mode: entry.Mode, Size: int64(len(entry.Data)),
			Uid: 0, Gid: 0, Uname: "root", Gname: "root", ModTime: time.Unix(0, 0).UTC(),
			Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
		}
		if err := writer.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := writer.Write(entry.Data); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if err := zipper.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func writeArMember(out io.Writer, name string, data []byte) error {
	if len(name) > 15 {
		return fmt.Errorf("debpack: ar member name %q is too long", name)
	}
	header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", name, 0, 0, 0, 0o100644, len(data))
	if len(header) != 60 {
		return fmt.Errorf("debpack: internal ar header is %d bytes", len(header))
	}
	if _, err := io.WriteString(out, header); err != nil {
		return err
	}
	if _, err := out.Write(data); err != nil {
		return err
	}
	if len(data)%2 != 0 {
		_, err := io.WriteString(out, "\n")
		return err
	}
	return nil
}
