// grok-proxy: 面向 grok(SuperGrok/X Premium 订阅)的极简 OAuth2 反向代理。
//
// 与通用 oauth-proxy 的区别:
//   - 只有一个上游 grok: URL / client_id / scope / 请求头全部内置写死,
//     config.json 只需关心 listen / api_key / cred_file 三个字段。
//   - 凭证存到单个文件 cred_file(如 /data/grok-auth.json)。
//
// 工作方式:
//
//	客户端 --(固定 api_key)--> grok-proxy --(自动刷新的 Bearer)--> cli-chat-proxy
//	代理自己维护 OAuth2 token: 首次 device code 登录,过期前 300s 自动刷新,
//	处理 refresh token 轮换并落盘;转发时自动带上 grok 要求的全套请求头。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ---------- grok 内置参数(与官方 grok-build 对齐,一般不用改) ----------

const (
	logTag = "grok" // 日志标签

	upstreamBase  = "https://cli-chat-proxy.grok.com"      // 上游 API
	oauthTokenURL = "https://auth.x.ai/oauth2/token"       // token 端点(刷新/轮询)
	oauthDevURL   = "https://auth.x.ai/oauth2/device/code" // device code 端点
	oauthClientID = "b1a00492-073a-47ea-816f-4c329264a828"
	oauthScope    = "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write workspaces:read workspaces:write"
	oauthReferrer = "grok-build"

	// grok CLI 版本号,请求头会带它。可用环境变量 GROK_CLIENT_VERSION 覆盖。
	defaultClientVersion = "1.0.13"

	defaultListen   = ":8080"
	defaultCredFile = "grok-auth.json"

	refreshSkewSec      = 300 // 过期前多少秒提前刷新
	refreshTimeoutSec   = 30  // 单次刷新请求的超时
	retryDelaySec       = 60  // 鉴权失败后的重试间隔
	oauthHTTPTimeoutSec = 60  // OAuth 单次请求超时
	devicePollInterval  = 5   // device code 轮询间隔(秒)
	ttlFallbackSec      = 3600
	loginTimeout        = 10 * time.Minute
)

// grokClientVersion 是发到上游的 x-grok-client-version 值。
var grokClientVersion = defaultClientVersion

// upstreamTarget 是编译期常量 URL 的解析结果(不可能失败)。
var upstreamTarget = func() *url.URL {
	u, err := url.Parse(upstreamBase)
	if err != nil {
		panic("bad upstreamBase: " + err.Error())
	}
	return u
}()

// ---------- 配置 ----------

type Config struct {
	Listen   string `json:"listen"`    // 监听地址,默认 ":8080"
	APIKey   string `json:"api_key"`   // 客户端访问用的固定 key(空则不校验)
	CredFile string `json:"cred_file"` // 凭证文件路径,默认 "grok-auth.json"
}

// App 是单个 grok 上游的全部运行时状态。
type App struct {
	credPath string
	headers  map[string]string // 转发时附加的静态头(启动时构造一次)
	proxy    *httputil.ReverseProxy

	refreshMu    sync.Mutex // 串行化刷新:refresh_token 不能并发使用
	mu           sync.Mutex
	accessToken  string
	refreshToken string
	expiresAt    time.Time
	ready        bool   // 是否已拿到可用 access_token
	authErr      string // 最近一次鉴权失败原因
}

// credFileData 是落盘凭证格式。与 oauth-proxy 的 cred 文件兼容,可直接改名复用。
type credFileData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// tokenResponse 是 OAuth token 端点标准响应(未用的字段交给 json 忽略)。
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"` // 若返回则说明轮换
}

// deviceCodeResponse 是 device code 端点响应。
type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// oauthHTTPClient 只用于 OAuth 请求(刷新/轮询/device code),不含流式转发。
var oauthHTTPClient = &http.Client{Timeout: oauthHTTPTimeoutSec * time.Second}

// ---------- 凭证读写 ----------

// credPath 返回凭证文件路径:配置的 cred_file,缺省 "grok-auth.json"。
func credPath(credFile string) string {
	p := credFile
	if p == "" {
		p = defaultCredFile
	}
	p = expandHome(p)
	if dir := filepath.Dir(p); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Printf("[%s] warn: mkdir cred dir: %v", logTag, err)
		}
	}
	return p
}

// loadCred 从凭证文件载入 access/refresh/expiry。返回是否成功载入。
func (a *App) loadCred() bool {
	data, err := os.ReadFile(a.credPath)
	if err != nil {
		return false // 文件不存在 → 需要登录
	}
	var c credFileData
	if json.Unmarshal(data, &c) != nil || c.RefreshToken == "" {
		return false
	}
	a.mu.Lock()
	a.refreshToken = c.RefreshToken
	a.accessToken = c.AccessToken
	a.expiresAt = c.ExpiresAt
	a.mu.Unlock()
	log.Printf("[%s] loaded cred from %s (expires %s)", logTag, a.credPath, formatTime(c.ExpiresAt))
	return true
}

// saveCred 把当前凭证写回文件(轮换/登录后必须持久化)。调用者须持有 a.mu。
func (a *App) saveCred() {
	data, _ := json.MarshalIndent(credFileData{
		AccessToken:  a.accessToken,
		RefreshToken: a.refreshToken,
		ExpiresAt:    a.expiresAt,
	}, "", "  ")
	if err := os.WriteFile(a.credPath, data, 0o600); err != nil {
		log.Printf("[%s] warn: save cred failed: %v", logTag, err)
	}
}

// ---------- token 管理 ----------

func (a *App) token() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.accessToken
}

// authStatus 返回 (ready, errMsg)。ready 只由 applyToken 置真,且与 access_token 同锁写入。
func (a *App) authStatus() (bool, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ready, a.authErr
}

func (a *App) setAuthErr(msg string) {
	a.mu.Lock()
	a.ready = false
	a.authErr = msg
	a.mu.Unlock()
}

// forceRefresh 无条件刷新一次(启动验证 / 定时 / 401 兜底共用)。
// 网络/5xx 等瞬时失败返回普通错误;refresh_token 被服务端拒绝返回 errCredInvalid。
func (a *App) forceRefresh(ctx context.Context) error {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()

	a.mu.Lock()
	rt := a.refreshToken
	a.mu.Unlock()
	if rt == "" {
		return errors.New("no refresh_token available")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", rt)
	form.Set("client_id", oauthClientID)
	form.Set("scope", oauthScope)

	status, body, err := oauthFormPost(ctx, oauthTokenURL, form, false)
	if err != nil {
		return err
	}
	if status == http.StatusBadRequest && isInvalidGrant(body) {
		return errCredInvalid
	}
	if status != http.StatusOK {
		return fmt.Errorf("refresh failed HTTP %d: %s", status, truncate(string(body), 300))
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return fmt.Errorf("parse token response: %w", err)
	}
	// 刷新不轮换时无需落盘:重启后 ensureAuth 总是先刷新验证一次。
	return a.applyToken(tr, false, "refreshed")
}

// errCredInvalid 表示 refresh_token 已被服务端吊销/拒绝,需要重新登录。
var errCredInvalid = errors.New("refresh_token rejected, re-login required")

// isInvalidGrant 判断 OAuth 错误响应是否为凭证失效(而非瞬时错误)。
func isInvalidGrant(body []byte) bool {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return false
	}
	switch e.Error {
	case "invalid_grant", "invalid_client", "expired_token":
		return true
	}
	return false
}

// applyToken 把 token 端点响应写入内存状态;persist 时落盘(登录必然落盘)。
// action 仅用于日志(如 "refreshed" / "login success")。
func (a *App) applyToken(tr tokenResponse, persist bool, action string) error {
	if tr.AccessToken == "" {
		return errors.New("token response missing access_token")
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	a.accessToken = tr.AccessToken
	ttl := tr.ExpiresIn
	if ttl <= 0 {
		ttl = ttlFallbackSec // 上游没给就保守按 1 小时
	}
	a.expiresAt = time.Now().Add(time.Duration(ttl) * time.Second)

	rotated := false
	if tr.RefreshToken != "" && tr.RefreshToken != a.refreshToken {
		a.refreshToken = tr.RefreshToken // 轮换:保存新的
		rotated = true
	}
	if persist || rotated {
		a.saveCred()
	}
	a.ready = true
	a.authErr = ""
	log.Printf("[%s] %s; expires %s (rotated_refresh_token=%v)",
		logTag, action, formatTime(a.expiresAt), rotated)
	return nil
}

// refreshLoop 睡到"过期前 refreshSkewSec 秒"再刷新,不依赖请求。
// 刷新失败(瞬时或凭证失效)统一返回 false,由 run 走 ensureAuth 重认证;ctx 取消返回 true。
func (a *App) refreshLoop(ctx context.Context) (ctxDone bool) {
	skew := time.Duration(refreshSkewSec) * time.Second
	for {
		a.mu.Lock()
		ready := a.ready
		exp := a.expiresAt
		a.mu.Unlock()
		if !ready {
			return false // 状态异常,交回 run 重新 ensureAuth
		}

		wait := time.Until(exp.Add(-skew))
		if wait < time.Second {
			wait = time.Second // 已到期/临近,尽快刷新(但避免忙等)
		}
		if !sleepCtx(ctx, wait) {
			return true
		}

		rctx, cancel := context.WithTimeout(ctx, refreshTimeoutSec*time.Second)
		err := a.forceRefresh(rctx)
		cancel()
		if err != nil {
			log.Printf("[%s] auto-refresh failed: %v", logTag, err)
			a.setAuthErr(err.Error())
			return false
		}
	}
}

// run 是生命周期主循环: 反复 ensureAuth(载入/刷新/必要时登录)直到成功,
// 然后进入定时刷新;任何刷新失败都回到 ensureAuth,由它决定重新登录还是重试。
func (a *App) run(ctx context.Context) {
	for {
		if err := a.ensureAuth(); err != nil {
			log.Printf("[%s] auth failed: %v (retry in %ds)", logTag, err, retryDelaySec)
			a.setAuthErr(err.Error())
			if !sleepCtx(ctx, retryDelaySec*time.Second) {
				return
			}
			continue
		}
		if a.refreshLoop(ctx) {
			return // ctx 取消
		}
		// 刷新失败:等一个退避周期后重新走 ensureAuth
		if !sleepCtx(ctx, retryDelaySec*time.Second) {
			return
		}
	}
}

// ensureAuth 保证有可用凭证:
//  1. 载入凭证文件;成功则刷新一次验证 refresh_token 有效性。
//  2. 无凭证 / 刷新失败 → 自动 device code 登录。
func (a *App) ensureAuth() error {
	if a.loadCred() {
		ctx, cancel := context.WithTimeout(context.Background(), refreshTimeoutSec*time.Second)
		err := a.forceRefresh(ctx)
		cancel()
		if err == nil {
			return nil
		}
		log.Printf("[%s] stored credential invalid/expired, re-login required", logTag)
	} else {
		log.Printf("[%s] no credential found, login required", logTag)
	}

	ctx, cancel := context.WithTimeout(context.Background(), loginTimeout)
	defer cancel()
	return a.login(ctx)
}

// ---------- Device Code 登录 (RFC 8628) ----------

// login 执行 OAuth2 Device Authorization Grant,成功后写入凭证并更新内存。
func (a *App) login(ctx context.Context) error {
	// 1) 请求 device code(带 grok 客户端版本/surface 头)
	form := url.Values{}
	form.Set("client_id", oauthClientID)
	form.Set("scope", oauthScope)
	form.Set("referrer", oauthReferrer)
	status, body, err := oauthFormPost(ctx, oauthDevURL, form, true)
	if err != nil {
		return fmt.Errorf("device code request: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("device code failed HTTP %d: %s", status, truncate(string(body), 300))
	}
	var dc deviceCodeResponse
	if err := json.Unmarshal(body, &dc); err != nil {
		return fmt.Errorf("parse device code: %w", err)
	}

	// 2) 提示用户去浏览器授权
	openURL := dc.VerificationURIComplete
	if openURL == "" {
		openURL = dc.VerificationURI
	}
	fmt.Printf("\n========================================================\n")
	fmt.Printf("  [%s] 需要登录。请在浏览器中打开以下地址完成授权:\n\n", logTag)
	fmt.Printf("    %s\n\n", openURL)
	fmt.Printf("  如未自动打开,请手动访问;user_code: %s\n", dc.UserCode)
	fmt.Printf("========================================================\n\n")
	tryOpenBrowser(openURL)

	// 3) 轮询 token 端点
	interval := dc.Interval
	if interval <= 0 {
		interval = devicePollInterval
	}
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		if !sleepCtx(ctx, time.Duration(interval)*time.Second) {
			return ctx.Err()
		}

		pf := url.Values{}
		pf.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		pf.Set("device_code", dc.DeviceCode)
		pf.Set("client_id", oauthClientID)
		status, pbody, err := oauthFormPost(ctx, oauthTokenURL, pf, true)
		if err != nil {
			log.Printf("[%s] poll error (will retry): %v", logTag, err)
			continue
		}
		if status == http.StatusOK {
			var tr tokenResponse
			if err := json.Unmarshal(pbody, &tr); err != nil {
				return fmt.Errorf("parse token: %w", err)
			}
			return a.applyToken(tr, true, "login success")
		}

		// 解析 OAuth 标准错误
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(pbody, &e)
		switch e.Error {
		case "authorization_pending":
			// 用户还没授权,继续等
		case "slow_down":
			interval += 5
		case "access_denied":
			return errors.New("login denied by user")
		case "expired_token":
			return errors.New("device code expired, please retry")
		default:
			log.Printf("[%s] poll HTTP %d: %s", logTag, status, truncate(string(pbody), 200))
		}
	}
	return errors.New("login timed out")
}

// oauthFormPost POST 表单到 OAuth 端点,统一带上 grok 客户端头。
// surface 为 true 时额外带 x-grok-client-surface(cli 登录流程用)。
// 返回 (HTTP 状态码, 响应体, 网络错误);状态码解释交给调用方。
func oauthFormPost(ctx context.Context, endpoint string, form url.Values, surface bool) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("x-grok-client-version", grokClientVersion)
	if surface {
		req.Header.Set("x-grok-client-surface", "cli")
	}
	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

// tryOpenBrowser 尽力自动打开浏览器(失败静默,用户可手动打开)。
func tryOpenBrowser(u string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", u}
	case "darwin":
		cmd, args = "open", []string{u}
	default:
		cmd, args = "xdg-open", []string{u}
	}
	_ = exec.Command(cmd, args...).Start()
}

// ---------- 转发 ----------

// userAgent 模拟 grok-shell 的 UA: grok-shell/<ver> (<os>; <arch>)。
func userAgent() string {
	osName := runtime.GOOS
	if osName == "darwin" {
		osName = "macos"
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	} else if arch == "arm64" {
		arch = "aarch64"
	}
	return fmt.Sprintf("grok-shell/%s (%s; %s)", grokClientVersion, osName, arch)
}

// grokHeaders 构造转发到 cli-chat-proxy 时附加的静态头(与官方 grok CLI 对齐)。
// 在 main 里 GROK_CLIENT_VERSION 覆盖后调用一次。
func grokHeaders() map[string]string {
	return map[string]string{
		"X-XAI-Token-Auth":         "xai-grok-cli",
		"x-authenticateresponse":   "authenticate-response",
		"x-grok-client-version":    grokClientVersion,
		"x-grok-client-identifier": "grok-shell",
		"x-grok-client-mode":       "interactive",
		"User-Agent":               userAgent(),
	}
}

// buildProxy 创建反向代理: 根路径透传,注入新鲜 Bearer + grok 静态头。
func (a *App) buildProxy() {
	target := upstreamTarget
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// 只改 scheme/host,路径原样透传(如 /v1/chat/completions)
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host

			// serve 已保证 ready(access_token 非空),这里只负责注入
			req.Header.Set("Authorization", "Bearer "+a.token())
			for k, v := range a.headers {
				req.Header.Set(k, v)
			}
		},
		Transport:     &refreshRoundTripper{a: a, base: http.DefaultTransport},
		FlushInterval: -1, // 立即 flush,支持 SSE 流式
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[%s] proxy error: %v", logTag, err)
			http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		},
	}
	a.proxy = rp
}

// serve 处理代理请求: 未就绪返回 503,就绪则转发。
func (a *App) serve(w http.ResponseWriter, r *http.Request) {
	ready, authErr := a.authStatus()
	if !ready {
		msg := "auth pending, please login"
		if authErr != "" {
			msg = "not ready: " + authErr
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": map[string]interface{}{
				"message": msg,
				"type":    "auth_pending",
			},
		})
		return
	}
	a.proxy.ServeHTTP(w, r)
}

// refreshRoundTripper 收到 401 时强制刷新一次并重试(被动兜底)。
type refreshRoundTripper struct {
	a    *App
	base http.RoundTripper
}

func (rt *refreshRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// 为可能的重试缓冲请求体(ReverseProxy 转发的 body 没有 GetBody,无法二次构造)
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	resp, err := rt.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	// 401:强制刷新后重试一次
	log.Printf("[%s] got 401, forcing refresh and retrying once", logTag)
	resp.Body.Close()
	if err := rt.a.forceRefresh(req.Context()); err != nil {
		rt.a.setAuthErr(err.Error())
		return nil, fmt.Errorf("forced refresh after 401 failed: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+rt.a.token())
	if bodyBytes != nil {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	return rt.base.RoundTrip(req)
}

// ---------- HTTP ----------

// authMiddleware 校验客户端固定 api_key(Authorization: Bearer 或 x-api-key)。
func authMiddleware(want string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want == "" { // 未配置则不校验
			next.ServeHTTP(w, r)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" {
			got = r.Header.Get("x-api-key")
		}
		if got != want {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"error": map[string]interface{}{
					"message": "unauthorized",
					"type":    "invalid_api_key",
				},
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- 主流程 ----------

func main() {
	// 用法: grok-proxy [config.json] [login]
	//   grok-proxy              用默认 config.json 启动(后台自动鉴权/登录)
	//   grok-proxy config.json  指定配置启动
	//   grok-proxy login        强制重新登录后退出
	cfgPath := "config.json"
	forceLogin := false
	for _, arg := range os.Args[1:] {
		if arg == "login" {
			forceLogin = true
		} else {
			cfgPath = arg
		}
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if v := os.Getenv("GROK_CLIENT_VERSION"); v != "" {
		grokClientVersion = v
	}

	a := &App{
		credPath: credPath(cfg.CredFile),
		headers:  grokHeaders(),
	}
	a.buildProxy()

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.serve)

	if forceLogin {
		// 强制登录模式: 登录成功后退出
		ctx, cancel := context.WithTimeout(context.Background(), loginTimeout)
		defer cancel()
		if err := a.login(ctx); err != nil {
			log.Fatalf("login failed: %v", err)
		}
		log.Printf("[%s] logged in, cred at %s", logTag, a.credPath)
		return
	}

	handler := authMiddleware(cfg.APIKey, mux)
	listen := cfg.Listen
	if listen == "" {
		listen = defaultListen
	}
	log.Printf("grok-proxy listening on %s; -> %s (grok client v%s, auth in background)",
		listen, upstreamBase, grokClientVersion)
	go a.run(context.Background())
	log.Fatal(http.ListenAndServe(listen, handler))
}

// ---------- 小工具 ----------

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = []byte(os.ExpandEnv(string(data))) // 支持 ${ENV_VAR}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + p[1:]
		}
	}
	return p
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// formatTime 按系统本地时区输出 RFC3339(如 +08:00),避免日志里一律是 UTC 的 Z。
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.In(time.Local).Format(time.RFC3339)
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// sleepCtx 睡眠 d,期间 ctx 取消则立即返回 false。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
