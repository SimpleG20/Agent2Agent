FROM golang:1.25-alpine AS builder
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -ldflags="-s -w" -o keygen .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /build/keygen .
ENTRYPOINT ["/app/keygen"]
