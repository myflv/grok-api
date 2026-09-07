// grok-proxy: 面向 grok(SuperGrok/X Premium 订阅)的极简 OAuth2 反向代理。
//
// 与通用 oauth-proxy 的区别:
//   - 只有一个上游 grok: URL / client_id / scope / 请求头全部内置写死,
//     config.json 只需关心 listen / client_api_key / name / cred_dir。
//   - 凭证存到 <cred_dir>/<name>.json(如 /data/grok.json)。
//
// 工作方式:
//
//	客户端 --(固定 client_api_key)--> grok-proxy --(自动刷新的 Bearer)--> cli-chat-proxy
//	代理自己维护 OAuth2 token: 首次 device code 登录,过期前 300s 自动刷新,
//	处理 refresh token 轮换并落盘;转发时自动带上 grok 要求的全套请求头。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ---------- grok 内置常量(与官方 grok-build 对齐,一般不用改) ----------

const (
	upstreamBase  = "https://cli-chat-proxy.grok.com"      // 上游 API
	oauthTokenURL = "https://auth.x.ai/oauth2/token"       // token 端点(刷新/轮询)
	oauthDevURL   = "https://auth.x.ai/oauth2/device/code" // device code 端点
	oauthClientID = "b1a00492-073a-47ea-816f-4c329264a828"
	oauthScope    = "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write workspaces:read workspaces:write"
	oauthReferrer = "grok-build"
	// grok CLI 版本号,请求头会带它。可用环境变量 GROK_CLIENT_VERSION 覆盖。
	defaultClientVersion = "1.0.13"
	refreshSkewSec       = 300 // 过期前多少秒提前刷新
	oauthHTTPTimeoutSec  = 60  // OAuth 请求(刷新/轮询)单次超时
	devicePollInterval   = 5   // device code 轮询间隔(秒)
)

// grokClientVersion 是发到上游的 x-grok-client-version 值。
var grokClientVersion = defaultClientVersion

// ---------- 配置 ----------

type Config struct {
	Listen       string `json:"listen"`         // 监听地址,默认 ":8080"
	ClientAPIKey string `json:"client_api_key"` // 客户端访问用的固定 key(空则不校验)
	Name         string `json:"name"`           // 路由前缀 + 凭证文件名,默认 "grok"
	CredDir      string `json:"cred_dir"`       // 凭证目录,默认 "./data"
}

// App 是单个 grok 上游的全部运行时状态。
type App struct {
	cfg      *Config
	name     string
	credPath string
	proxy    *httputil.ReverseProxy

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

// tokenResponse 是 OAuth token 端点标准响应。
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"` // 若返回则说明轮换
	Scope        string `json:"scope"`
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

// resolveCredPath 返回凭证路径 <cred_dir>/<name>.json。
func (a *App) resolveCredPath() {
	dir := a.cfg.CredDir
	if dir == "" {
		dir = "./data"
	}
	dir = expandHome(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("[%s] warn: mkdir cred dir: %v", a.name, err)
	}
	a.credPath = dir + "/" + a.name + ".json"
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
	log.Printf("[%s] loaded cred from %s (expires %s)", a.name, a.credPath, formatTime(c.ExpiresAt))
	return true
}

// saveCred 把当前凭证写回文件(轮换后必须持久化)。调用者须持有 a.mu。
func (a *App) saveCred() {
	data, _ := json.MarshalIndent(credFileData{
		AccessToken:  a.accessToken,
		RefreshToken: a.refreshToken,
		ExpiresAt:    a.expiresAt,
	}, "", "  ")
	if err := os.WriteFile(a.credPath, data, 0o600); err != nil {
		log.Printf("[%s] warn: save cred failed: %v", a.name, err)
	}
}

// ---------- token 管理 ----------

func (a *App) token() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.accessToken
}

// isReady 返回是否已拿到可用 token。
func (a *App) isReady() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ready && a.accessToken != ""
}

// authStatus 返回 (ready, errMsg)。
func (a *App) authStatus() (bool, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ready && a.accessToken != "", a.authErr
}

func (a *App) setAuthErr(msg string) {
	a.mu.Lock()
	a.ready = false
	a.authErr = msg
	a.mu.Unlock()
}

// forceRefresh 无条件刷新一次(启动验证 / 401 兜底)。
func (a *App) forceRefresh(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.refreshLocked(ctx)
}

// refreshLocked 执行标准 OAuth2 refresh_token 刷新。调用者须持有 a.mu。
func (a *App) refreshLocked(ctx context.Context) error {
	if a.refreshToken == "" {
		return fmt.Errorf("no refresh_token available")
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", a.refreshToken)
	form.Set("client_id", oauthClientID)
	form.Set("scope", oauthScope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthTokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("x-grok-client-version", grokClientVersion)

	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("refresh request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh failed HTTP %d: %s", resp.StatusCode, truncate(string(body), 300))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return fmt.Errorf("parse token response: %w", err)
	}
	if tr.AccessToken == "" {
		return fmt.Errorf("token response missing access_token")
	}

	a.accessToken = tr.AccessToken
	ttl := tr.ExpiresIn
	if ttl <= 0 {
		ttl = 3600 // 上游没给就保守按 1 小时
	}
	a.expiresAt = time.Now().Add(time.Duration(ttl) * time.Second)

	rotated := false
	if tr.RefreshToken != "" && tr.RefreshToken != a.refreshToken {
		a.refreshToken = tr.RefreshToken // 轮换:保存新的
		rotated = true
	}
	a.ready = true
	a.authErr = ""
	a.saveCred()
	log.Printf("[%s] refreshed; expires %s (rotated_refresh_token=%v)",
		a.name, formatTime(a.expiresAt), rotated)
	return nil
}

// autoRefreshLoop 后台定时刷新: 睡到"过期前 300s"再刷新,不依赖请求。
func (a *App) autoRefreshLoop(ctx context.Context) {
	skew := refreshSkewSec * time.Second
	for {
		a.mu.Lock()
		ready := a.ready
		exp := a.expiresAt
		a.mu.Unlock()

		if !ready {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		wait := time.Until(exp.Add(-skew))
		if wait < time.Second {
			wait = time.Second // 已到期/临近,尽快刷新(但避免忙等)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := a.forceRefresh(rctx)
		cancel()
		if err != nil {
			log.Printf("[%s] auto-refresh failed, retry in 60s: %v", a.name, err)
			a.setAuthErr(err.Error())
			select {
			case <-ctx.Done():
				return
			case <-time.After(60 * time.Second):
			}
		}
	}
}

// run 是生命周期: 先保证有可用凭证,再进入定时刷新循环。
func (a *App) run(ctx context.Context) {
	for {
		if err := a.ensureAuth(); err != nil {
			log.Printf("[%s] auth failed: %v (retry in 60s)", a.name, err)
			a.setAuthErr(err.Error())
			select {
			case <-ctx.Done():
				return
			case <-time.After(60 * time.Second):
			}
			continue
		}
		a.autoRefreshLoop(ctx)
		return
	}
}

// ensureAuth 保证有可用凭证:
//  1. 载入凭证文件;成功则刷新一次验证 refresh_token 有效性。
//  2. 无凭证 / 刷新失败 → 自动 device code 登录。
func (a *App) ensureAuth() error {
	if a.loadCred() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := a.forceRefresh(ctx)
		cancel()
		if err == nil {
			return nil
		}
		log.Printf("[%s] stored credential invalid/expired, re-login required", a.name)
	} else {
		log.Printf("[%s] no credential found, login required", a.name)
	}

	loginCtx, loginCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer loginCancel()
	return a.login(loginCtx)
}

// ---------- Device Code 登录 (RFC 8628) ----------

// login 执行 OAuth2 Device Authorization Grant,成功后写入凭证并更新内存。
func (a *App) login(ctx context.Context) error {
	// 1) 请求 device code(带 grok 客户端版本/surface 头)
	form := url.Values{}
	form.Set("client_id", oauthClientID)
	form.Set("scope", oauthScope)
	form.Set("referrer", oauthReferrer)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthDevURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("x-grok-client-version", grokClientVersion)
	req.Header.Set("x-grok-client-surface", "cli")
	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("device code request: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("device code failed HTTP %d: %s", resp.StatusCode, truncate(string(body), 300))
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
	fmt.Printf("  [%s] 需要登录。请在浏览器中打开以下地址完成授权:\n\n", a.name)
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
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(interval) * time.Second):
		}

		pf := url.Values{}
		pf.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		pf.Set("device_code", dc.DeviceCode)
		pf.Set("client_id", oauthClientID)
		preq, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthTokenURL,
			strings.NewReader(pf.Encode()))
		if err != nil {
			return err
		}
		preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		preq.Header.Set("x-grok-client-version", grokClientVersion)
		preq.Header.Set("x-grok-client-surface", "cli")
		presp, err := oauthHTTPClient.Do(preq)
		if err != nil {
			log.Printf("[%s] poll error (will retry): %v", a.name, err)
			continue
		}
		pbody, _ := io.ReadAll(presp.Body)
		presp.Body.Close()

		if presp.StatusCode == http.StatusOK {
			var tr tokenResponse
			if err := json.Unmarshal(pbody, &tr); err != nil {
				return fmt.Errorf("parse token: %w", err)
			}
			a.mu.Lock()
			a.accessToken = tr.AccessToken
			a.refreshToken = tr.RefreshToken
			ttl := tr.ExpiresIn
			if ttl <= 0 {
				ttl = 3600
			}
			a.expiresAt = time.Now().Add(time.Duration(ttl) * time.Second)
			a.ready = true
			a.authErr = ""
			a.saveCred()
			a.mu.Unlock()
			log.Printf("[%s] login success; cred saved to %s", a.name, a.credPath)
			return nil
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
			return fmt.Errorf("login denied by user")
		case "expired_token":
			return fmt.Errorf("device code expired, please retry")
		default:
			log.Printf("[%s] poll HTTP %d: %s", a.name, presp.StatusCode, truncate(string(pbody), 200))
		}
	}
	return fmt.Errorf("login timed out")
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

// buildProxy 创建反向代理: 注入新鲜 Bearer + grok 请求头。
func (a *App) buildProxy() error {
	target, err := url.Parse(upstreamBase)
	if err != nil {
		return fmt.Errorf("bad base_url: %w", err)
	}
	prefix := "/" + a.name
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			path := strings.TrimPrefix(req.URL.Path, prefix)
			req.URL.Path = strings.TrimRight(target.Path, "/") + path
			req.Host = target.Host

			tok := a.token()
			if tok == "" {
				// 无可用 token,用 header 标记,Transport 里拦截
				req.Header.Set("X-OAuthProxy-Error", "no access token available")
				return
			}
			req.Header.Set("Authorization", "Bearer "+tok)
			// 与官方 grok CLI 对齐的请求头(version 可被 GROK_CLIENT_VERSION 覆盖)
			req.Header.Set("X-XAI-Token-Auth", "xai-grok-cli")
			req.Header.Set("x-authenticateresponse", "authenticate-response")
			req.Header.Set("x-grok-client-version", grokClientVersion)
			req.Header.Set("x-grok-client-identifier", "grok-shell")
			req.Header.Set("x-grok-client-mode", "interactive")
			req.Header.Set("User-Agent", userAgent())
		},
		Transport:     &refreshRoundTripper{a: a, base: http.DefaultTransport},
		FlushInterval: -1, // 立即 flush,支持 SSE 流式
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[%s] proxy error: %v", a.name, err)
			http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		},
	}
	a.proxy = rp
	return nil
}

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

// serve 处理该上游的请求: 未就绪返回 503,就绪则转发。
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
	if e := req.Header.Get("X-OAuthProxy-Error"); e != "" {
		return nil, fmt.Errorf("token error: %s", e)
	}

	// 为可能的重试缓冲请求体
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
	log.Printf("[%s] got 401, forcing refresh and retrying once", rt.a.name)
	resp.Body.Close()
	if err := rt.a.forceRefresh(req.Context()); err != nil {
		rt.a.setAuthErr(err.Error())
		return nil, fmt.Errorf("forced refresh after 401 failed: %w", err)
	}
	tok := rt.a.token()
	if tok == "" {
		return nil, fmt.Errorf("no access token after refresh")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if bodyBytes != nil {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	return rt.base.RoundTrip(req)
}

// ---------- HTTP ----------

// authMiddleware 校验客户端固定 api_key(Authorization: Bearer 或 x-api-key)。
// /healthz 不需要鉴权。
func authMiddleware(want string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		if want == "" { // 未配置则不校验
			next.ServeHTTP(w, r)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" {
			got = r.Header.Get("x-api-key")
		}
		if got != want {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
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

	a := &App{cfg: cfg, name: cfg.Name}
	a.resolveCredPath()
	if err := a.buildProxy(); err != nil {
		log.Fatalf("%v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		ready, authErr := a.authStatus()
		status := map[string]interface{}{"name": a.name, "ready": ready}
		if authErr != "" {
			status["error"] = authErr
		}
		code := http.StatusOK
		if !ready {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, map[string]interface{}{"ok": ready, "grok": status})
	})
	mux.HandleFunc("/"+a.name+"/", func(w http.ResponseWriter, r *http.Request) {
		a.serve(w, r)
	})

	if forceLogin {
		// 强制登录模式: 登录成功后退出
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := a.login(ctx); err != nil {
			log.Fatalf("login failed: %v", err)
		}
		log.Printf("[%s] logged in, cred at %s", a.name, a.credPath)
		return
	}

	handler := authMiddleware(cfg.ClientAPIKey, mux)
	listen := cfg.Listen
	if listen == "" {
		listen = ":8080"
	}
	log.Printf("grok-proxy %s listening on %s; route /%s/ -> %s (auth runs in background)",
		grokClientVersion, listen, a.name, upstreamBase)
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
	if cfg.Name == "" {
		cfg.Name = "grok"
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
