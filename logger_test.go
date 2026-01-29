package cego_test

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	cego "github.com/cego/go-lib"
	"github.com/cego/go-lib/headers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestLogger(t *testing.T) {
	t.Run("it constructs", func(t *testing.T) {
		logger := cego.NewLogger()
		logger.Debug("debug")
		assert.NotNil(t, logger)
	})

	t.Run("it can get request attr", func(t *testing.T) {
		// Prepare
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(headers.XForwardedFor, "85.4.4.5, 10.0.0.1")
		req.Header.Set(headers.UserAgent, "curl/8.7")
		req.Header.Set(headers.Cookie, "verysecretstuff")
		req.Header.Set(headers.Authorization, "alsoverysecretstuff")
		logger := cego.NewMockLogger()
		logger.On("Debug", mock.Anything, mock.Anything).Return()

		// Do
		logger.Debug("Epic request data is attached", cego.GetSlogAttrFromRequest(req))

		// Assert
		validators := map[string]func(string) bool{
			"client.ip":           func(v string) bool { return v == "192.0.2.1" },
			"client.address":      func(v string) bool { return v == "85.4.4.5, 10.0.0.1" },
			"user_agent.original": func(v string) bool { return v == "curl/8.7" },
			"http.request.headers.raw": func(v string) bool {
				return v == "{\"Authorization\":[\"\\u003cmasked\\u003e\"],\"Cookie\":[\"\\u003cmasked\\u003e\"],\"User-Agent\":[\"curl/8.7\"],\"X-Forwarded-For\":[\"85.4.4.5, 10.0.0.1\"]}"
			},
		}
		logger.AssertCalled(t, "Debug", "Epic request data is attached", mock.MatchedBy(MatchSlogGroup("", validators)))
	})

	t.Run("it can get err attr", func(t *testing.T) {
		// Prepare
		err := errors.New("test error")
		logger := cego.NewMockLogger()
		logger.On("Error", mock.Anything, mock.Anything).Return()

		// Do
		logger.Error("Something has failed here", cego.GetSlogAttrFromError(err))

		// Assert
		validators := map[string]func(string) bool{
			"message":     func(v string) bool { return v == "test error" },
			"stack_trace": func(v string) bool { return len(v) > 0 },
		}
		logger.AssertCalled(t, "Error", "Something has failed here", mock.MatchedBy(MatchSlogGroup("error", validators)))
	})
}

func MatchSlogGroup(expectedKey string, validators map[string]func(string) bool) func(any) bool {
	return func(arg any) bool {
		if slice, ok := arg.([]any); ok && len(slice) > 0 {
			arg = slice[0]
		}

		a, ok := arg.(slog.Attr)
		if !ok {
			return false
		}

		if a.Key != expectedKey {
			return false
		}

		satisfied := make(map[string]bool)
		for k := range validators {
			satisfied[k] = false
		}

		for _, attr := range a.Value.Group() {
			if validate, exists := validators[attr.Key]; exists {
				if validate(attr.Value.String()) {
					satisfied[attr.Key] = true
				}
			}
		}

		for _, ok := range satisfied {
			if !ok {
				return false
			}
		}

		return true
	}
}
