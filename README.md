# grok-proxy

一个面向 **grok** 的极简 OAuth2 反向代理。客户端只用一个固定的 `api_key`,
代理自己维护 grok 的 OAuth2 token —— 首次自动 device-code 登录,之后过期前自动刷新、
处理 token 轮换、落盘持久化,转发时自动带上 grok 官方 CLI 同款的请求头。

**与通用 oauth-proxy 不同**:grok 相关的 URL、client_id、scope、请求头全部内置写死,
config.json 只有 3 个字段。零第三方依赖(纯 Go 标准库)。

## config.json(就这么多)

```json
{
  "listen": "0.0.0.0:8080",
  "api_key": "sk-local-fixed",
  "cred_file": "/data/grok-auth.json"
}
```

| 字段 | 说明 | 默认 |
|------|------|------|
| `listen` | 监听地址 | `:8080` |
| `api_key` | 客户端访问本代理的固定 key(空则不校验) | — |
| `cred_file` | 凭证文件路径(支持 `~`) | `grok-auth.json` |

其余参数(上游 URL、OAuth 端点、client_id、scope、`skew_sec=300`、超时、请求头)
全部内置,与官方 grok CLI 对齐;客户端版本可用环境变量 `GROK_CLIENT_VERSION` 覆盖。

> 内置参数可以这样看:
> 上游 `https://cli-chat-proxy.grok.com`,OAuth `auth.x.ai`,
> client_id `b1a00492-...`,请求头带 `x-grok-client-version` / `X-XAI-Token-Auth`
> 等,grok CLI 更新后如需同步改 `main.go` 顶部的常量即可。

路由固定为 `/grok/...`。

## 运行

```bash
go build -o grok-proxy .
./grok-proxy config.json
# 首次会打印授权地址,浏览器登录后即自动开始服务
```

命令:`grok-proxy [config.json] [login]` —— 带 `login` 时强制重新登录后退出。

## 客户端调用示例

```bash
curl -X POST http://127.0.0.1:5001/grok/v1/chat/completions \
  -H "Authorization: Bearer sk-local-fixed" \
  -H "Content-Type: application/json" \
  -d '{"model":"grok-4","messages":[{"role":"user","content":"hi"}]}'
```

## Docker / docker-compose (NAS)

镜像发布在 GitHub Container Registry: `ghcr.io/myflv/grok2api`(支持 amd64 / arm64)。

1. 准备目录,放入 `config.json`(见上,`cred_file` 为 `/data/grok-auth.json`)和 `docker-compose.yml`;
2. 启动:

   ```bash
   docker compose up -d
   ```

3. **首次登录**(容器内无浏览器,看日志拿授权地址):

   ```bash
   docker compose logs -f grok-proxy
   # 日志里会打印: https://accounts.x.ai/... user_code: XXXX-XXXX
   # 在任意浏览器打开该地址完成授权,容器自动写入 ./data/grok-auth.json
   ```

   授权成功后凭证持久化在 `./data/`,之后重启容器自动复用并后台刷新
   (除非 refresh_token 被吊销 —— 删掉 `./data/grok-auth.json` 重启重新登录即可)。

4. 调用:`http://<NAS_IP>:5001/grok/v1/chat/completions`(带 `Authorization: Bearer <api_key>`)。

## 与 llm-proxy 配合

```yaml
- name: grok-4.5
  type: responses
  model: grok-4.5
  api_key: sk-local-fixed
  base_url: http://127.0.0.1:5001/grok/v1
```

## 从 oauth-proxy 迁移

凭证格式完全兼容:直接复用原 `cred_file`(如 `/data/grok-auth.json`)即可,
`config.json` 里删掉不用的字段(upstreams、name、cred_dir、token_url、client_id 等),
`client_api_key` 改名为 `api_key`。
