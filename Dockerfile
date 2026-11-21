# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/dropcatch ./cmd/dropcatch

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -H -u 10001 dropcatch \
 && mkdir -p /data && chown dropcatch:dropcatch /data
COPY --from=build /out/dropcatch /usr/local/bin/dropcatch
USER dropcatch
ENV DB_PATH=/data/dropcatch.db \
    LISTEN_ADDR=:8080 \
    TZ=UTC
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=6s --start-period=10s --retries=3 CMD ["dropcatch", "healthcheck"]
ENTRYPOINT ["dropcatch"]
