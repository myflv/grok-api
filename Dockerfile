# ---- 构建阶段 ----
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /grok-proxy .

# ---- 运行阶段(极小镜像) ----
FROM alpine:latest
# tzdata: 让 TZ=Asia/Shanghai 这类环境变量生效(默认 UTC)
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /grok-proxy /app/grok-proxy
# 凭证文件默认写到 /data(用卷持久化)
VOLUME ["/data"]
EXPOSE 8080
# 可通过 docker-compose 覆盖 TZ, 如 Asia/Shanghai
ENV TZ=UTC
ENTRYPOINT ["/app/grok-proxy"]
CMD ["/app/config.json"]
