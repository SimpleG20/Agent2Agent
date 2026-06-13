# Stage 1: Build
FROM golang:1.25-alpine AS builder
WORKDIR /build

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -ldflags="-s -w -extldflags=-static" \
    -o key-guard ./cmd/key-guard/

# Stage 2: Distroless runtime
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /build/key-guard .

EXPOSE 3000
ENTRYPOINT ["/app/key-guard"]
