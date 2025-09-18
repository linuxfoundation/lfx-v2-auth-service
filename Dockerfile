# Copyright The Linux Foundation and each contributor to LFX.
# SPDX-License-Identifier: MIT

# checkov:skip=CKV_DOCKER_7:No free access to Chainguard versioned labels.
# hadolint global ignore=DL3007

FROM cgr.dev/chainguard/go:latest AS builder

# Set necessary environment variables needed for our image. Allow building to
# other architectures via cross-compilation build-arg.
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH

# Move to working directory /build
WORKDIR /build

# Download dependencies to go modules cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the code into the container
COPY . .

# Generate API code and build the packages
RUN go build -o /go/bin/auth-service -trimpath -ldflags="-w -s" github.com/linuxfoundation/lfx-v2-auth-service/cmd/server

# Run our go binary standalone
FROM cgr.dev/chainguard/static:latest

# Implicit with base image; setting explicitly for linters.
USER nonroot

# Expose port 8080 for health checks and metrics (if needed)
EXPOSE 8080

COPY --from=builder /go/bin/auth-service /cmd/auth-service

ENTRYPOINT ["/cmd/auth-service"]
