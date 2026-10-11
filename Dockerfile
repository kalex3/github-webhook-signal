FROM golang:1.27 AS builder

WORKDIR /app

COPY main.go .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o gh-webhook main.go

FROM scratch

COPY --from=builder /app/gh-webhook .

USER 1000:1000

ENTRYPOINT ["./gh-webhook"]
