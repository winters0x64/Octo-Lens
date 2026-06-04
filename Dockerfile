FROM golang:1.25-alpine AS build

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /github-pat-monitor .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -h /app patmonitor

COPY --from=build /github-pat-monitor /usr/local/bin/github-pat-monitor
COPY --from=build /src/policy.yaml /app/policy.yaml

USER patmonitor
WORKDIR /app

EXPOSE 8080

ENTRYPOINT ["github-pat-monitor"]
CMD ["serve", "--addr", "0.0.0.0", "--port", "8080"]
