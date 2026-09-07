# grok-proxy

一个面向 **grok** 的极简 OAuth2 反向代理:客户端只用一个固定 `api_key`,
代理自动维护 grok 的 token(首次 device-code 登录、过期前自动刷新、轮换落盘),
并把请求转发到 cli-chat-proxy。URL、client_id、scope、请求头全部内置,
config.json 只有 3 个字段。零第三方依赖(纯 Go 标准库)。

## config.json

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

grok 客户端版本与请求头一起写死在 `main.go` 顶部常量,grok 更新后同步升级(版本号变了头部参数通常也变了,不做运行时覆盖)。

路由为根路径 `/`:所有路径原样透传上游,直接按 OpenAI 兼容格式调用。

## 运行

```bash
go build -o grok-proxy .
./grok-proxy config.json
# 首次会打印授权地址,浏览器登录后即自动开始服务
```

命令:`grok-proxy [config.json] [login]` —— 带 `login` 时强制重新登录后退出。

## 客户端调用示例

```bash
curl -X POST http://127.0.0.1:5001/v1/chat/completions \
  -H "Authorization: Bearer sk-local-fixed" \
  -H "Content-Type: application/json" \
  -d '{"model":"grok-4.6","messages":[{"role":"user","content":"hi"}]}'
```

## Docker / docker-compose (NAS)

镜像发布在 GitHub Container Registry: `ghcr.io/myflv/grok-api`(支持 amd64 / arm64)。

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

4. 调用:`http://<NAS_IP>:5001/v1/chat/completions`(带 `Authorization: Bearer <api_key>`)。

## 与 llm-proxy 配合

```yaml
- name: grok-4.6
  type: responses
  model: grok-4.6
  api_key: sk-local-fixed
  base_url: http://127.0.0.1:5001/v1
```
