package oidcauth_test

import (
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/cego/go-lib/v2/oidcauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	sessionCookieName = "__Host-oidcauth_session"
	refreshCookieName = "__Host-oidcauth_refresh"
)

// loggedIn logs a reader in, and returns a client that does not follow redirects.
func loggedIn(t *testing.T, idp *fakeIDP) (string, *http.Client) {
	t.Helper()
	server, client := newTestServer(t, idp, "reader")
	idp.LoginAs(map[string]any{"email": "reader@example.com", "client_roles": []any{"reader"}})

	response := browserGet(t, client, server.URL+"/protected")
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusOK, response.StatusCode)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return server.URL, client
}

// expireSession drops the session cookie, as a browser does when the id token runs out.
func expireSession(t *testing.T, client *http.Client, serverURL string) {
	t.Helper()
	target, err := url.Parse(serverURL)
	require.NoError(t, err)
	client.Jar.SetCookies(target, []*http.Cookie{{Name: sessionCookieName, Path: "/", Secure: true, MaxAge: -1}})
}

func jarCookie(t *testing.T, client *http.Client, serverURL, name string) string {
	t.Helper()
	target, err := url.Parse(serverURL)
	require.NoError(t, err)
	for _, cookie := range client.Jar.Cookies(target) {
		if cookie.Name == name {
			return cookie.Value
		}
	}

	return ""
}

func TestRefresh(t *testing.T) {
	t.Run("an expired session is renewed without a visit to the provider", func(t *testing.T) {
		idp := newFakeIDP(t)
		serverURL, client := loggedIn(t, idp)
		expireSession(t, client, serverURL)

		response := browserGet(t, client, serverURL+"/protected")
		defer func() { _ = response.Body.Close() }()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.Contains(t, string(body), "reader@example.com")
		assert.Equal(t, 1, idp.Refreshes())
		assert.NotEmpty(t, jarCookie(t, client, serverURL, sessionCookieName))

		again := browserGet(t, client, serverURL+"/protected")
		defer func() { _ = again.Body.Close() }()
		assert.Equal(t, http.StatusOK, again.StatusCode)
		assert.Equal(t, 1, idp.Refreshes(), "the renewed session is used until it runs out")
	})

	t.Run("an htmx request is answered instead of told to log in", func(t *testing.T) {
		idp := newFakeIDP(t)
		serverURL, client := loggedIn(t, idp)
		expireSession(t, client, serverURL)

		request, err := http.NewRequest(http.MethodGet, serverURL+"/protected", nil)
		require.NoError(t, err)
		request.Header.Set("HX-Request", "true")
		response, err := client.Do(request)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.Empty(t, response.Header.Get("HX-Redirect"))
	})

	t.Run("a post is carried out instead of lost to a login", func(t *testing.T) {
		idp := newFakeIDP(t)
		serverURL, client := loggedIn(t, idp)
		expireSession(t, client, serverURL)

		response, err := client.Post(serverURL+"/protected", "", nil)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("a role taken away at the provider is gone after the refresh", func(t *testing.T) {
		idp := newFakeIDP(t)
		serverURL, client := loggedIn(t, idp)
		idp.ChangeSessions(map[string]any{"email": "reader@example.com", "client_roles": []any{}})
		expireSession(t, client, serverURL)

		response := browserGet(t, client, serverURL+"/protected")
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusForbidden, response.StatusCode)
	})

	t.Run("a session ended at the provider goes back to login", func(t *testing.T) {
		idp := newFakeIDP(t)
		serverURL, client := loggedIn(t, idp)
		idp.EndSessions()
		expireSession(t, client, serverURL)

		response := browserGet(t, client, serverURL+"/protected")
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusFound, response.StatusCode)
		assert.Contains(t, response.Header.Get("Location"), idp.IssuerURL()+"/auth")
		assert.Empty(t, jarCookie(t, client, serverURL, refreshCookieName))
	})

	t.Run("requests holding the same refresh token share one refresh when the provider rotates it", func(t *testing.T) {
		idp := newFakeIDP(t)
		idp.RotateRefreshTokens()
		serverURL, client := loggedIn(t, idp)
		refreshToken := jarCookie(t, client, serverURL, refreshCookieName)
		require.NotEmpty(t, refreshToken)

		bare := *client
		bare.Jar = nil
		statuses := make([]int, 5)
		var wait sync.WaitGroup
		for i := range statuses {
			wait.Go(func() {
				request, _ := http.NewRequest(http.MethodGet, serverURL+"/protected", nil)
				request.Header.Set("Accept", "text/html")
				request.AddCookie(&http.Cookie{Name: refreshCookieName, Value: refreshToken})
				response, err := bare.Do(request)
				if err != nil {
					return
				}
				_ = response.Body.Close()
				statuses[i] = response.StatusCode
			})
		}
		wait.Wait()

		assert.Equal(t, []int{200, 200, 200, 200, 200}, statuses)
		assert.Equal(t, 1, idp.Refreshes())
	})

	t.Run("a bearer token is not renewed by a refresh cookie", func(t *testing.T) {
		idp := newFakeIDP(t)
		serverURL, client := loggedIn(t, idp)
		expireSession(t, client, serverURL)

		request, err := http.NewRequest(http.MethodGet, serverURL+"/protected", nil)
		require.NoError(t, err)
		request.Header.Set("Authorization", "Bearer not-a-token")
		response, err := client.Do(request)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
		assert.Equal(t, 0, idp.Refreshes())
	})

	t.Run("logout drops the refresh token", func(t *testing.T) {
		idp := newFakeIDP(t)
		serverURL, client := loggedIn(t, idp)

		response, err := client.Post(serverURL+oidcauth.LogoutPath, "", nil)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		assert.Empty(t, jarCookie(t, client, serverURL, refreshCookieName))
		assert.Empty(t, jarCookie(t, client, serverURL, sessionCookieName))
	})
}
