package cego

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

type TestAllGoodHandler struct{}

func (t *TestAllGoodHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("All good !!!"))
}

func TestForwardAuthHandler(t *testing.T) {
	t.Run("forward auth handler passthrough", func(t *testing.T) {
		allGoodHandler := &TestAllGoodHandler{}
		logger := NewMockLogger()
		httpmock.Activate(t)
		defer httpmock.Reset()
		httpmock.RegisterResponder("GET", "https://sso.example.com/auth", httpmock.NewStringResponder(200, "Cookie n' ACL matches let him in"))

		request, _ := http.NewRequest(http.MethodGet, "/someurl", nil)
		response := httptest.NewRecorder()

		httpClient := &http.Client{
			Timeout: time.Second * 5,
		}
		f := NewForwardAuth(logger, "https://sso.example.com/auth", "example.com", WithHTTPClient(httpClient))
		f.Handler(allGoodHandler).ServeHTTP(response, request)

		assert.Equal(t, response.Code, 200)
		assert.Equal(t, response.Body.String(), "All good  !!!")
	})

	t.Run("forward auth handlerfunc passthrough", func(t *testing.T) {
		logger := NewMockLogger()
		httpmock.Activate(t)
		defer httpmock.Reset()
		httpmock.RegisterResponder("GET", "https://sso.example.com/auth", httpmock.NewStringResponder(200, "Cookie n' ACL matches let him in"))

		request, _ := http.NewRequest(http.MethodGet, "/someurl", nil)
		response := httptest.NewRecorder()

		f := NewForwardAuth(logger, "https://sso.example.com/auth", "example.com")
		f.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			_, _ = w.Write([]byte("All good !!!"))
		}).ServeHTTP(response, request)

		assert.Equal(t, response.Code, 200)
		assert.Equal(t, response.Body.String(), "All good !!!")
	})

	t.Run("forward auth handler unauthorized", func(t *testing.T) {
		allGoodHandler := &TestAllGoodHandler{}
		logger := NewMockLogger()
		httpmock.Activate(t)
		defer httpmock.Reset()
		httpmock.RegisterResponder("GET", "https://sso.example.com/auth", httpmock.NewStringResponder(401, "Did you sent a cookie?"))

		request, _ := http.NewRequest(http.MethodGet, "/someurl", nil)
		response := httptest.NewRecorder()

		f := NewForwardAuth(logger, "https://sso.example.com/auth", "example.com")
		f.Handler(allGoodHandler).ServeHTTP(response, request)

		assert.Equal(t, response.Code, 401)
		assert.Equal(t, response.Body.String(), "Did you sent a cookie?")
	})

	t.Run("forward auth handler forbidden", func(t *testing.T) {
		allGoodHandler := &TestAllGoodHandler{}
		logger := NewMockLogger()
		httpmock.Activate(t)
		defer httpmock.Reset()
		httpmock.RegisterResponder("GET", "https://sso.example.com/auth", httpmock.NewStringResponder(403, "Valid login, but you have been forbidden"))

		request, _ := http.NewRequest(http.MethodGet, "/someurl", nil)
		response := httptest.NewRecorder()

		f := NewForwardAuth(logger, "https://sso.example.com/auth", "example.com")
		f.Handler(allGoodHandler).ServeHTTP(response, request)

		assert.Equal(t, response.Code, 403)
		assert.Equal(t, response.Body.String(), "Valid login, but you have been forbidden")
	})
}
