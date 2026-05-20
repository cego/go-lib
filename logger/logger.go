package logger

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/cego/go-lib/v2/headers"
)

// defaultAsyncCapacity is the buffer depth of the shared stdout
// AsyncWriter. Picked so a short stdout stall (a few hundred ms at
// typical service log rates) doesn't drop lines, while a sustained
// stall doesn't grow memory without bound.
const defaultAsyncCapacity = 4096

var (
	stdoutAsyncOnce sync.Once
	stdoutAsync     *AsyncWriter
)

// stdoutWriter returns the process-wide AsyncWriter wrapping os.Stdout,
// lazily initialised. All loggers built by this package share it so
// they share one drain goroutine and one buffer.
func stdoutWriter() *AsyncWriter {
	stdoutAsyncOnce.Do(func() {
		stdoutAsync = NewAsyncWriter(os.Stdout, defaultAsyncCapacity)
	})
	return stdoutAsync
}

// Flush blocks until all log lines queued so far have been written to
// stdout. Call it from your graceful shutdown path so the final lines
// reach the log collector before the process exits.
func Flush() {
	if w := stdoutAsync; w != nil {
		w.Flush()
	}
}

// Dropped returns the number of log lines dropped because the async
// buffer was saturated. A non-zero value means stdout's consumer is
// not keeping up.
func Dropped() uint64 {
	if w := stdoutAsync; w != nil {
		return w.Dropped()
	}
	return 0
}

type Logger interface {
	Debug(message string, args ...any)
	Info(message string, args ...any)
	Error(message string, args ...any)
}

func New() *slog.Logger {
	return newSlogger(stdoutWriter(), slog.LevelDebug)
}

func NewWithLevel(level slog.Level) *slog.Logger {
	return newSlogger(stdoutWriter(), level)
}

func newSlogger(w io.Writer, level slog.Level) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: level,
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
	return slog.New(slog.NewJSONHandler(w, opts))
}

func GetSlogAttrFromError(err error) slog.Attr {
	return slog.Group("error",
		slog.String("message", err.Error()),
		slog.String("stack_trace", string(debug.Stack())),
	)
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
