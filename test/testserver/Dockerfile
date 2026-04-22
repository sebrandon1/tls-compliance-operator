FROM --platform=$BUILDPLATFORM golang:1.26 AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /app

COPY go.mod ./
COPY main.go ./

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w" -o tls-test-server .

FROM scratch

COPY --from=builder /app/tls-test-server /tls-test-server

ENTRYPOINT ["/tls-test-server"]
