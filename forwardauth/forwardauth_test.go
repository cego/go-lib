package forwardauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cego/go-lib/forwardauth"
	"github.com/cego/go-lib/logger"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

const testHost = "example.com"

type TestAllGoodHandler struct{}

func (t *TestAllGoodHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("All good !!!"))
}

func TestForwardAuthHandler(t *testing.T) {
	t.Run("forward auth handler passthrough", func(t *testing.T) {
		allGoodHandler := &TestAllGoodHandler{}
		l := logger.NewMock()
		httpmock.Activate(t)
		defer httpmock.Reset()
		httpmock.RegisterResponder("GET", "https://sso.example.com/auth", httpmock.NewStringResponder(200, "Cookie n' ACL matches let him in"))

		request, _ := http.NewRequest(http.MethodGet, "/someurl", nil)
		response := httptest.NewRecorder()

		httpClient := &http.Client{
			Timeout: time.Second * 5,
		}
		f := forwardauth.New(l, "https://sso.example.com/auth", "example.com", forwardauth.WithHTTPClient(httpClient))
		f.Handler(allGoodHandler).ServeHTTP(response, request)

		assert.Equal(t, 200, response.Code)
		assert.Equal(t, "All good !!!", response.Body.String())
	})

	t.Run("forward auth handlerfunc passthrough", func(t *testing.T) {
		l := logger.NewMock()
		httpmock.Activate(t)
		defer httpmock.Reset()
		httpmock.RegisterResponder("GET", "https://sso.example.com/auth", httpmock.NewStringResponder(200, "Cookie n' ACL matches let him in"))

		request, _ := http.NewRequest(http.MethodGet, "/someurl", nil)
		response := httptest.NewRecorder()

		f := forwardauth.New(l, "https://sso.example.com/auth", testHost)
		f.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			_, _ = w.Write([]byte("All good !!!"))
		}).ServeHTTP(response, request)

		assert.Equal(t, 200, response.Code)
		assert.Equal(t, "All good !!!", response.Body.String())
	})

	t.Run("forward auth handler unauthorized", func(t *testing.T) {
		allGoodHandler := &TestAllGoodHandler{}
		l := logger.NewMock()
		httpmock.Activate(t)
		defer httpmock.Reset()
		httpmock.RegisterResponder("GET", "https://sso.example.com/auth", httpmock.NewStringResponder(401, "Did you send a cookie?"))

		request, _ := http.NewRequest(http.MethodGet, "/someurl", nil)
		response := httptest.NewRecorder()

		f := forwardauth.New(l, "https://sso.example.com/auth", testHost)
		f.Handler(allGoodHandler).ServeHTTP(response, request)

		assert.Equal(t, 401, response.Code)
		assert.Equal(t, "Did you send a cookie?", response.Body.String())
	})

	t.Run("forward auth handler forbidden", func(t *testing.T) {
		allGoodHandler := &TestAllGoodHandler{}
		l := logger.NewMock()
		httpmock.Activate(t)
		defer httpmock.Reset()
		httpmock.RegisterResponder("GET", "https://sso.example.com/auth", httpmock.NewStringResponder(403, "Valid login, but you have been forbidden"))

		request, _ := http.NewRequest(http.MethodGet, "/someurl", nil)
		response := httptest.NewRecorder()

		f := forwardauth.New(l, "https://sso.example.com/auth", testHost)
		f.Handler(allGoodHandler).ServeHTTP(response, request)

		assert.Equal(t, 403, response.Code)
		assert.Equal(t, "Valid login, but you have been forbidden", response.Body.String())
	})
}
