// Command retentionops-deb builds the official Debian release artifact without depending on a
// host dpkg installation, so the same bytes can be reproduced on Linux or macOS.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/solutions-optigm/retentionops-connector/internal/debpack"
)

func main() {
	version := flag.String("version", "", "package version")
	architecture := flag.String("arch", "", "Debian architecture")
	binary := flag.String("binary", "", "built connector binary")
	output := flag.String("output", "", "output .deb")
	flag.Parse()
	if *version == "" || *architecture == "" || *binary == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "version, arch, binary and output are required")
		os.Exit(2)
	}
	replacements := map[string]string{"@VERSION@": *version, "@ARCH@": *architecture}
	control := must(debpack.TemplateEntry("packaging/debian/control", "control", 0o644, replacements))
	postinst := must(debpack.ReadEntry("packaging/debian/postinst", "postinst", 0o755))
	postrm := must(debpack.ReadEntry("packaging/debian/postrm", "postrm", 0o755))
	connector := must(debpack.ReadEntry(*binary, "usr/bin/retentionops-connector", 0o755))
	service := must(debpack.ReadEntry("deploy/systemd/retentionops-connector.service", "usr/lib/systemd/system/retentionops-connector.service", 0o644))
	sysusers := must(debpack.ReadEntry("packaging/debian/retentionops-connector.sysusers", "usr/lib/sysusers.d/retentionops-connector.conf", 0o644))
	tmpfiles := must(debpack.ReadEntry("packaging/debian/retentionops-connector.tmpfiles", "usr/lib/tmpfiles.d/retentionops-connector.conf", 0o644))
	readme := must(debpack.ReadEntry("README.md", "usr/share/doc/retentionops-connector/README.md", 0o644))
	license := must(debpack.ReadEntry("LICENSE", "usr/share/licenses/retentionops-connector/LICENSE", 0o644))
	if err := debpack.Write(*output, debpack.Package{
		Control: []debpack.Entry{control, postinst, postrm},
		Data:    []debpack.Entry{connector, service, sysusers, tmpfiles, readme, license},
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func must[T any](value T, err error) T {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return value
}
