package cego

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/cego/go-lib/headers"
)

type Logger interface {
	Debug(message string, args ...any)
	Info(message string, args ...any)
	Error(message string, args ...any)
}

func NewLogger() Logger {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.MessageKey {
				a.Key = "message"
			}
			if a.Key == slog.LevelKey {
				a.Key = "log.level"
			}
			if a.Key == slog.TimeKey {
				a.Key = "@timestamp"
				a.Value = slog.StringValue(a.Value.Time().UTC().Format(time.RFC3339Nano))
			}
			return a
		},
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

func GetSlogAttrFromError(err error) slog.Attr {
	var attrs []slog.Attr

	attrs = append(attrs, slog.String("error.message", err.Error()))
	attrs = append(attrs, slog.String("error.stack_trace", string(debug.Stack())))

	attr := slog.Attr{}
	attr.Value = slog.GroupValue(attrs...)
	return attr
}

func GetSlogAttrFromRequest(req *http.Request) slog.Attr {
	var attrs []slog.Attr

	reqHeaders := req.Header

	remoteAddr := req.RemoteAddr
	clientIp, _, _ := net.SplitHostPort(remoteAddr)
	attrs = append(attrs, slog.String("client.ip", clientIp))

	if reqHeaders.Get(headers.XForwardedFor) != "" {
		attrs = append(attrs, slog.String("client.address", reqHeaders.Get(headers.XForwardedFor)))
	}

	if reqHeaders.Get(headers.UserAgent) != "" {
		attrs = append(attrs, slog.String("user_agent.original", reqHeaders.Get(headers.UserAgent)))
	}

	h := reqHeaders.Clone()
	if h.Get(headers.Cookie) != "" {
		h.Set(headers.Cookie, "<masked>")
	}
	if h.Get(headers.Authorization) != "" {
		h.Set(headers.Authorization, "<masked>")
	}
	if len(h) > 0 {
		headersJsonMarshalled, _ := json.Marshal(h)
		attrs = append(attrs, slog.String("http.request.headers.raw", string(headersJsonMarshalled)))
	}

	attr := slog.Attr{}
	attr.Value = slog.GroupValue(attrs...)
	return attr
}
