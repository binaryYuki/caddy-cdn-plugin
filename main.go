package edge

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Edge{})

	httpcaddyfile.RegisterHandlerDirective("edge", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		var m Edge
		if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
			return nil, err
		}
		return &m, nil
	})

	httpcaddyfile.RegisterDirectiveOrder("edge", "before", "reverse_proxy")
}

type Edge struct {
	// 响应头里注入：X-Server: <value>
	XServer string `json:"x_server,omitempty"`

	// true = admin 站点（全部 no-store）
	Admin bool `json:"admin,omitempty"`

	// 200 缓存秒数（仅 Admin=false 时生效）
	OkCacheSeconds int `json:"ok_cache_seconds,omitempty"`

	// 是否启用自定义 404
	Custom404 bool `json:"custom_404,omitempty"`
}

func (Edge) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.edge",
		New: func() caddy.Module { return new(Edge) },
	}
}

func (m *Edge) Provision(ctx caddy.Context) error {
	if m.XServer == "" {
		m.XServer = "Catyuki-CDN"
	}
	if m.OkCacheSeconds <= 0 {
		m.OkCacheSeconds = 86400
	}
	// 默认开（你也可以在 Caddyfile 里关掉）
	if !m.Custom404 {
		m.Custom404 = true
	}
	return nil
}

// Caddyfile:
//
//	edge {
//	  x_server Catyuki-CDN
//	  admin true|false
//	  ok_cache_seconds 86400
//	  custom_404 true|false
//	}
func (m *Edge) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "x_server":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.XServer = d.Val()

			case "admin":
				if !d.NextArg() {
					return d.ArgErr()
				}
				b, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.ArgErr()
				}
				m.Admin = b

			case "ok_cache_seconds":
				if !d.NextArg() {
					return d.ArgErr()
				}
				n, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.ArgErr()
				}
				m.OkCacheSeconds = n

			case "custom_404":
				if !d.NextArg() {
					return d.ArgErr()
				}
				b, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.ArgErr()
				}
				m.Custom404 = b

			default:
				return d.Errf("unrecognized directive: %s", d.Val())
			}
		}
	}
	return nil
}

func (m Edge) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	isLogo := r.URL.Path == "/logo" || r.URL.Path == "/logo.jpg"

	// rewrite: /logo 或 /logo.jpg -> /public/logo.jpg
	if isLogo {
		r.URL.Path = "/public/logo.jpg"
	}

	rw := &edgeRW{
		ResponseWriter: w,
		req:            r,
		cfg:            m,
		isLogoJPG:      isLogo,
	}

	return next.ServeHTTP(rw, r)
}

type edgeRW struct {
	http.ResponseWriter
	req *http.Request
	cfg Edge

	wroteHeader bool
	status      int

	isLogoJPG bool
}

func (e *edgeRW) WriteHeader(code int) {
	if e.wroteHeader {
		return
	}
	e.wroteHeader = true
	e.status = code

	e.applyBaseHeaders()

	e.applyCacheHeaders(code)

	h := e.Header()
	h.Del("Server")
	h.Del("Via")

	if e.isLogoJPG {
		h.Set("Content-Type", "image/jpeg")
	}

	// 自定义 404：仅 text/html 才输出页面，否则空 body
	if e.cfg.Custom404 && code == http.StatusNotFound {
		h.Set("Cache-Control", "no-cache, must-revalidate")

		if wantsHTML(e.req) {
			h.Set("Content-Type", "text/html; charset=utf-8")

			page := render404Page(e.req)
			e.ResponseWriter.WriteHeader(http.StatusNotFound)
			_, _ = e.ResponseWriter.Write(page)
			return
		}

		e.ResponseWriter.WriteHeader(http.StatusNotFound)
		return
	}

	e.ResponseWriter.WriteHeader(code)
}

func (e *edgeRW) Write(p []byte) (int, error) {
	if !e.wroteHeader {
		e.WriteHeader(http.StatusOK)
	}

	if e.cfg.Custom404 && e.status == http.StatusNotFound {
		return len(p), nil
	}

	return e.ResponseWriter.Write(p)
}

func (e *edgeRW) applyBaseHeaders() {
	h := e.Header()

	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Server", e.cfg.XServer)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-XSS-Protection", "1; mode=block")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
	h.Set("X-Robots-Tag", "noindex, nofollow")
}

func (e *edgeRW) applyCacheHeaders(code int) {
	h := e.Header()

	if e.cfg.Admin {
		h.Set("Cache-Control", "no-store")
		return
	}

	if code == http.StatusOK {
		h.Set("Cache-Control", "public, max-age="+strconv.Itoa(e.cfg.OkCacheSeconds)+", immutable")
	} else {
		h.Set("Cache-Control", "no-cache, must-revalidate")
	}
}

func wantsHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/html")
}

func detectLang(r *http.Request) string {
	q := r.URL.Query().Get("lang")
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "en" || q == "en-us" || q == "en-gb" {
		return "en"
	}
	if q == "zh" || q == "zh-cn" || q == "zh-hans" {
		return "zh"
	}

	al := strings.ToLower(r.Header.Get("Accept-Language"))
	// 简单粗暴：有 en 优先英文，否则中文
	if strings.Contains(al, "en") {
		return "en"
	}
	return "zh"
}

func pickTraceID(r *http.Request) string {
	// 你想叫 Trace-ID，那就优先读它；没有再读 X-Request-ID
	if v := strings.TrimSpace(r.Header.Get("Trace-ID")); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("X-Request-ID")); v != "" {
		return v
	}
	return ""
}

func render404Page(r *http.Request) []byte {
	lang := detectLang(r)
	host := strings.TrimSpace(r.Host)
	traceID := pickTraceID(r)
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	// 为了“零依赖 + 零模板引擎”，这里用安全的最小替换（不插用户输入 HTML）。
	// host/trace/ts 都走 HTML escape。
	hHost := htmlEscape(host)
	hTrace := htmlEscape(traceID)
	hTs := htmlEscape(ts)

	var tpl string
	if lang == "en" {
		tpl = notFoundEN
	} else {
		tpl = notFoundZH
	}

	// 替换占位符
	s := strings.ReplaceAll(tpl, "{{HOST}}", hHost)
	s = strings.ReplaceAll(s, "{{TRACE_ID}}", hTrace)
	s = strings.ReplaceAll(s, "{{TS}}", hTs)

	return []byte(s)
}

// 极简 HTML escape（够用：& < > " '）
func htmlEscape(s string) string {
	if s == "" {
		return ""
	}
	var b bytes.Buffer
	b.Grow(len(s) + 16)
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

const notFoundZH = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - 找不到页面 | Yuki Cat Labs</title>

    <link rel="dns-prefetch" href="https://cdn.catyuki.com">
    <link rel="preconnect" href="https://cdn.catyuki.com" crossorigin>

    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background-color: #fdfbf7;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            color: #545454;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
            position: relative;
        }

        .container {
            background-color: #ffffff;
            display: flex;
            flex-direction: row;
            align-items: center;
            justify-content: center;
            max-width: 1180px;
            width: 100%;
            border-radius: 24px;
            box-shadow: 0 15px 40px rgba(0, 0, 0, 0.06);
            padding: 64px;
            gap: 60px;
            border: 1px solid rgba(0,0,0,0.03);
        }

        .content { flex: 1; max-width: 480px; }

        h1 {
            font-size: 72px;
            font-weight: 700;
            color: #2c3e50;
            margin-bottom: 12px;
            line-height: 1;
            letter-spacing: -1px;
        }

        h2 {
            font-size: 28px;
            font-weight: 400;
            color: #95a5a6;
            margin-bottom: 36px;
        }

        .description-text {
            font-size: 18px;
            line-height: 1.7;
            margin-bottom: 32px;
            color: #636e72;
        }

        .bucket-info {
            margin-top: 24px;
            padding-top: 20px;
            border-top: 2px solid #f0f2f5;
        }

        .bucket-info h3 {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 10px;
            color: #2c3e50;
        }

        .bucket-info p { font-size: 16px; line-height: 1.6; }
        .meta {
            margin-top: 14px;
            padding: 12px 14px;
            background: #fbfbfb;
            border: 1px solid rgba(0,0,0,0.06);
            border-radius: 12px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 13px;
            color: #444;
            word-break: break-all;
        }

        a {
            color: #d35400; text-decoration: none;
            font-weight: 600; transition: color 0.2s ease;
        }
        a:hover { color: #e67e22; text-decoration: underline; }

        .illustration {
            flex: 1.4;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .illustration img {
            width: 100%;
            height: auto;
            border-radius: 12px;
            transition: transform 0.3s ease;
        }

        @media (max-width: 900px) {
            body { padding-top: 80px; align-items: flex-start; }
            .container {
                flex-direction: column-reverse;
                text-align: center;
                padding: 40px 30px;
                gap: 40px;
                max-width: 100%;
            }
            .content { max-width: 100%; }
            h1 { font-size: 56px; }
            h2 { font-size: 24px; }
            .illustration { flex: auto; width: 100%; }
            .meta { text-align: left; }
        }
    </style>
</head>
<body>

<div class="container">
    <div class="content">
        <h1>404</h1>
        <h2>哎呀，找不到页面了</h2>

        <p class="description-text">
            我们的猫咪大厨似乎把你要找的页面当作调料加进拉面里了。<br>
            请检查链接是否正确，或者返回首页看看其他美味。
        </p>

        <div class="bucket-info">
            <h3>需要帮助？</h3>
            <p>
                返回 <a href="javascript:history.back()">上一级</a> 或联系管理员。
            </p>

            <div class="meta">
                <div><strong>如果联系支持，请提供以下信息：</strong></div>
                <div>主机: {{HOST}}</div>
                <div>Trace-ID: {{TRACE_ID}}</div>
                <div>时间戳: {{TS}}</div>
            </div>
        </div>
    </div>

    <div class="illustration">
        <img src="https://cdn.catyuki.com/public/404_Illustration.png" alt="猫咪拉面师傅找不到调料的 404 插图">
    </div>
</div>

</body>
</html>
`

const notFoundEN = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found | Yuki Cat Labs</title>

    <link rel="dns-prefetch" href="https://cdn.catyuki.com">
    <link rel="preconnect" href="https://cdn.catyuki.com" crossorigin>

    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background-color: #fdfbf7;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            color: #545454;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
            position: relative;
        }

        .container {
            background-color: #ffffff;
            display: flex;
            flex-direction: row;
            align-items: center;
            justify-content: center;
            max-width: 1180px;
            width: 100%;
            border-radius: 24px;
            box-shadow: 0 15px 40px rgba(0, 0, 0, 0.06);
            padding: 64px;
            gap: 60px;
            border: 1px solid rgba(0,0,0,0.03);
        }

        .content { flex: 1; max-width: 480px; }

        h1 {
            font-size: 72px;
            font-weight: 700;
            color: #2c3e50;
            margin-bottom: 12px;
            line-height: 1;
            letter-spacing: -1px;
        }

        h2 {
            font-size: 28px;
            font-weight: 400;
            color: #95a5a6;
            margin-bottom: 36px;
        }

        .description-text {
            font-size: 18px;
            line-height: 1.7;
            margin-bottom: 32px;
            color: #636e72;
        }

        .bucket-info {
            margin-top: 24px;
            padding-top: 20px;
            border-top: 2px solid #f0f2f5;
        }

        .bucket-info h3 {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 10px;
            color: #2c3e50;
        }

        .bucket-info p { font-size: 16px; line-height: 1.6; }
        .meta {
            margin-top: 14px;
            padding: 12px 14px;
            background: #fbfbfb;
            border: 1px solid rgba(0,0,0,0.06);
            border-radius: 12px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 13px;
            color: #444;
            word-break: break-all;
        }

        a {
            color: #d35400; text-decoration: none;
            font-weight: 600; transition: color 0.2s ease;
        }
        a:hover { color: #e67e22; text-decoration: underline; }

        .illustration {
            flex: 1.4;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .illustration img {
            width: 100%;
            height: auto;
            border-radius: 12px;
            transition: transform 0.3s ease;
        }

        @media (max-width: 900px) {
            body { padding-top: 80px; align-items: flex-start; }
            .container {
                flex-direction: column-reverse;
                text-align: center;
                padding: 40px 30px;
                gap: 40px;
                max-width: 100%;
            }
            .content { max-width: 100%; }
            h1 { font-size: 56px; }
            h2 { font-size: 24px; }
            .illustration { flex: auto; width: 100%; }
            .meta { text-align: left; }
        }
    </style>
</head>
<body>

<div class="container">
    <div class="content">
        <h1>404</h1>
        <h2>Oops, Page Not Found</h2>

        <p class="description-text">
            Our cat chef seems to have used the page you're looking for as seasoning in the ramen.<br>
            Please check the URL, or return to the homepage for other delicacies.
        </p>

        <div class="bucket-info">
            <h3>Need Help?</h3>
            <p>
                Return to <a href="javascript:history.back()">Previous Page</a> or contact the administrator.
            </p>

            <div class="meta">
                <div><strong>Please include these details if you contact support:</strong></div>
                <div>Host: {{HOST}}</div>
                <div>Trace-ID: {{TRACE_ID}}</div>
                <div>Timestamp: {{TS}}</div>
            </div>
        </div>
    </div>

    <div class="illustration">
        <img src="https://cdn.catyuki.com/public/404_Illustration.png" alt="404 illustration of a cat chef frantically looking for seasoning">
    </div>
</div>

</body>
</html>
`

var (
	_ caddy.Provisioner           = (*Edge)(nil)
	_ caddyhttp.MiddlewareHandler = (*Edge)(nil)
	_ caddyfile.Unmarshaler       = (*Edge)(nil)
)
