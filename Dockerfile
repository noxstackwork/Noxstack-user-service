# syntax=docker/dockerfile:1

# --- Build stage ---
FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o app ./main.go

# --- Runtime stage ---
FROM alpine:3.19
WORKDIR /app
RUN adduser -D -u 10001 appuser
COPY --from=builder /src/app ./app
COPY --from=builder /src/migrations ./migrations
COPY --from=builder /src/run_migrations.sh ./run_migrations.sh
COPY --from=builder /src/config ./config
COPY --from=builder /src/.env ./
RUN chmod +x ./run_migrations.sh ./app
USER appuser
ENV GIN_MODE=release
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD wget --spider -q http://localhost:8080/health || exit 1
ENTRYPOINT ["/bin/sh", "-c", "./run_migrations.sh && ./app"]

