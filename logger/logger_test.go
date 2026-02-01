package logger_test

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cego/go-lib/headers"
	"github.com/cego/go-lib/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestLogger(t *testing.T) {
	t.Run("it constructs", func(t *testing.T) {
		l := logger.New()
		l.Debug("debug")
		assert.NotNil(t, l)
	})

	t.Run("it constructs with level", func(t *testing.T) {
		l := logger.NewWithLevel(slog.LevelInfo)
		l.Info("info")
		assert.NotNil(t, l)
	})

	t.Run("it can get request attr", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(headers.XForwardedFor, "85.4.4.5, 10.0.0.1")
		req.Header.Set(headers.UserAgent, "curl/8.7")
		req.Header.Set(headers.Cookie, "verysecretstuff")
		req.Header.Set(headers.Authorization, "alsoverysecretstuff")
		l := logger.NewMock()
		l.On("Debug", mock.Anything, mock.Anything).Return()

		l.Debug("Epic request data is attached", logger.GetSlogAttrFromRequest(req))

		validators := map[string]func(string) bool{
			"client.ip":           func(v string) bool { return v == "192.0.2.1" },
			"client.address":      func(v string) bool { return v == "85.4.4.5, 10.0.0.1" },
			"user_agent.original": func(v string) bool { return v == "curl/8.7" },
			"http.request.headers.raw": func(v string) bool {
				return v == "{\"Authorization\":[\"\\u003cmasked\\u003e\"],\"Cookie\":[\"\\u003cmasked\\u003e\"],\"User-Agent\":[\"curl/8.7\"],\"X-Forwarded-For\":[\"85.4.4.5, 10.0.0.1\"]}"
			},
		}
		l.AssertCalled(t, "Debug", "Epic request data is attached", mock.MatchedBy(MatchSlogGroup("", validators)))
	})

	t.Run("it can get err attr", func(t *testing.T) {
		err := errors.New("test error")
		l := logger.NewMock()
		l.On("Error", mock.Anything, mock.Anything).Return()

		l.Error("Something has failed here", logger.GetSlogAttrFromError(err))

		validators := map[string]func(string) bool{
			"message":     func(v string) bool { return v == "test error" },
			"stack_trace": func(v string) bool { return len(v) > 0 },
		}
		l.AssertCalled(t, "Error", "Something has failed here", mock.MatchedBy(MatchSlogGroup("error", validators)))
	})
}

func MatchSlogGroup(expectedKey string, validators map[string]func(string) bool) func(any) bool {
	return func(arg any) bool {
		attr := extractSlogAttr(arg)
		if attr == nil || attr.Key != expectedKey {
			return false
		}
		return validateAllAttrs(attr.Value.Group(), validators)
	}
}

func extractSlogAttr(arg any) *slog.Attr {
	if slice, ok := arg.([]any); ok && len(slice) > 0 {
		arg = slice[0]
	}
	if a, ok := arg.(slog.Attr); ok {
		return &a
	}
	return nil
}

func validateAllAttrs(attrs []slog.Attr, validators map[string]func(string) bool) bool {
	satisfied := make(map[string]bool, len(validators))
	for _, attr := range attrs {
		if validate, exists := validators[attr.Key]; exists && validate(attr.Value.String()) {
			satisfied[attr.Key] = true
		}
	}
	return len(satisfied) == len(validators)
}
