FROM ghcr.io/flashbots/chain-monitor:v0.0.57 AS bin
FROM alpine
RUN apk add --no-cache ca-certificates netcat-openbsd
WORKDIR /app
COPY --from=bin /app/chain-monitor ./chain-monitor
COPY entrypoint.sh ./entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]
