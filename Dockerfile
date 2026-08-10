# Reproducible, dependency-free image for a binary that holds delete rights on a customer's
# production database. Nothing but the binary and a CA bundle ships.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.1.0-dev
RUN CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/retentionops-connector ./cmd/retentionops-connector

# scratch rather than alpine: the connector needs no shell, no package manager and no libc, so
# it ships with none. There is nothing in this image for a compromised process to pivot into.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/retentionops-connector /retentionops-connector

# 65532 is the conventional non-root uid for distroless-style images. The connector never needs
# to write outside the volumes an operator mounts for identity and state.
USER 65532:65532
VOLUME ["/var/lib/retentionops"]

ENTRYPOINT ["/retentionops-connector"]
CMD ["run", "--config", "/etc/retentionops/connector.yaml"]
