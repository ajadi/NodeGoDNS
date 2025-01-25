FROM golang:1.20-alpine AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

RUN go build -o nodegodns main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/nodegodns .
COPY --from=builder /app/certs certs
COPY --from=builder /app/zones zones
COPY --from=builder /app/backups backups

CMD ["./nodegodns"]
