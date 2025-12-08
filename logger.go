package cego

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"
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

func GetSlogAttrFromRequest(req *http.Request) slog.Attr {
	userAgent := req.Header.Get("User-Agent")
	xForwardedFor := req.Header.Get("X-Forwarded-For")
	remoteAddr := req.RemoteAddr

	clientIp, _, _ := net.SplitHostPort(remoteAddr)

	var attrs []slog.Attr
	attrs = append(attrs, slog.String("url.original", req.RequestURI))
	attrs = append(attrs, slog.String("http.request.method", req.Method))
	attrs = append(attrs, slog.String("url.scheme", req.URL.Scheme))
	attrs = append(attrs, slog.String("url.domain", req.URL.Hostname()))
	attrs = append(attrs, slog.String("url.port", req.URL.Port()))
	attrs = append(attrs, slog.String("url.path", req.URL.RawPath))
	attrs = append(attrs, slog.String("url.query", req.URL.RawQuery))
	attrs = append(attrs, slog.String("url.fragment", req.URL.RawFragment))
	attrs = append(attrs, slog.String("client.ip", clientIp))
	attrs = append(attrs, slog.String("user_agent.original", userAgent))
	if xForwardedFor != "" {
		attrs = append(attrs, slog.String("client.address", xForwardedFor))
	}

	headers := req.Header.Clone()
	headers.Set("Cookie", "<masked>")
	headers.Set("Authorization", "<masked>")
	headersJsonMarshalled, _ := json.Marshal(headers)
	attrs = append(attrs, slog.String("http.request.headers.raw", string(headersJsonMarshalled)))

	attr := slog.Attr{}
	attr.Value = slog.GroupValue(attrs...)
	return attr
}
