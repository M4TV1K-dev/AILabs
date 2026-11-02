# Stage 1: Build binary
FROM golang:1.23-alpine AS builder

WORKDIR /build

COPY go.mod ./
RUN go mod download || true

COPY . .

# Build static Linux binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o auditor ./cmd/auditor

# Stage 2: Runtime image with Nmap
FROM alpine:3.20

# Install Nmap, official scripts, curl, ca-certificates, and libpcap
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    ca-certificates \
    curl \
    libpcap

# Download and register the vulners.nse script for NSE CVE detection
RUN mkdir -p /usr/share/nmap/scripts && \
    curl -sSL https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse -o /usr/share/nmap/scripts/vulners.nse && \
    nmap --script-updatedb || true

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /build/auditor /app/auditor

# Copy default config template
COPY config.json /app/config.json

# Default environment configuration (host.docker.internal connects to host machine's LLM)
ENV SERVER_PORT=":8080" \
    LLM_ENDPOINT="http://host.docker.internal:5000/v1" \
    LLM_PROVIDER="openai" \
    LLM_MODEL="qwen2.5" \
    NMAP_PATH="nmap"

EXPOSE 8080

ENTRYPOINT ["/app/auditor"]
CMD ["-config", "/app/config.json", "-no-browser"]
