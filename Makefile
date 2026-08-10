VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BINARY  := retentionops-connector
PLATFORMS := linux/amd64 linux/arm64

.PHONY: help deps build test lint vet fmt check dist sbom clean

help:
	@echo "deps    resolve and pin the module graph (writes go.sum)"
	@echo "check   fmt + vet + test — what CI runs"
	@echo "build   build $(BINARY) for this host"
	@echo "dist    build every release platform into dist/"
	@echo "sbom    write a CycloneDX inventory to dist/sbom.cdx.json"

# go.sum is not committed pre-resolved: run this once after cloning, or after changing go.mod.
deps:
	go mod tidy

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY) ./cmd/$(BINARY)

test:
	go test ./... -race -count=1

vet:
	go vet ./...

fmt:
	gofmt -l -w .

# Refuses to pass if anything is unformatted, rather than reformatting silently: a CI run that
# mutates the tree is a CI run whose result depends on where it ran.
check:
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt found unformatted files" && exit 1)
	go vet ./...
	go test ./... -race -count=1

# Reproducible: -trimpath removes local paths, CGO_ENABLED=0 removes the host toolchain, and
# the version is the only build-time input. Two builds of one tag produce identical bytes.
dist:
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath \
			-ldflags "$(LDFLAGS)" -o dist/$(BINARY)-$$os-$$arch ./cmd/$(BINARY); \
	done
	@cd dist && shasum -a 256 $(BINARY)-* > checksums.txt && cat checksums.txt

sbom:
	@mkdir -p dist
	go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest mod -json -output dist/sbom.cdx.json

clean:
	rm -rf dist
