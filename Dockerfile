FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /go-vuln-gate ./cmd/go-vuln-gate

FROM golang:1.25-alpine

RUN apk add --no-cache git

RUN go install golang.org/x/vuln/cmd/govulncheck@latest

COPY --from=builder /go-vuln-gate /usr/local/bin/go-vuln-gate

ENTRYPOINT ["go-vuln-gate"]
