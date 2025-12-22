package edge

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed templates/*.html
var tplFS embed.FS

func renderPage(r *http.Request, status int) []byte {
	lang := detectLang(r)
	name := fmt.Sprintf("templates/%d.%s.html", status, lang)

	b, err := fs.ReadFile(tplFS, name)
	if err != nil {
		// Fallback
		return []byte(strconv.Itoa(status))
	}

	host := htmlEscape(strings.TrimSpace(r.Host))
	traceID := htmlEscape(pickTraceID(r))
	ts := htmlEscape(strconv.FormatInt(time.Now().Unix(), 10))

	s := string(b)
	s = strings.ReplaceAll(s, "{{HOST}}", host)
	s = strings.ReplaceAll(s, "{{TRACE_ID}}", traceID)
	s = strings.ReplaceAll(s, "{{TS}}", ts)

	return []byte(s)
}
