package oidcauth_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cego/go-lib/v2/oidcauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type idpTransport func(*http.Request) (*http.Response, error)

func (f idpTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func replayRefresh(t *testing.T, client *http.Client, target, token string) *http.Response {
	t.Helper()
	bare := *client
	bare.Jar = nil
	req, err := http.NewRequest(http.MethodGet, target+"/protected", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: refreshCookieName, Value: token})
	res, err := bare.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

func TestLogoutRevokesRefresh(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		name := "reusable"
		if rotate {
			name = "rotating"
		}
		t.Run(name, func(t *testing.T) {
			idp := newFakeIDP(t)
			if rotate {
				idp.RotateRefreshTokens()
			}
			target, client := loggedIn(t, idp)
			original := jarCookie(t, client, target, refreshCookieName)
			expireSession(t, client, target)
			res := browserGet(t, client, target+"/protected")
			require.NoError(t, res.Body.Close())
			require.Equal(t, http.StatusOK, res.StatusCode)
			rotated := jarCookie(t, client, target, refreshCookieName)
			res, err := client.Post(target+oidcauth.LogoutPath, "", nil)
			require.NoError(t, err)
			require.NoError(t, res.Body.Close())
			require.Equal(t, http.StatusSeeOther, res.StatusCode)
			assert.Empty(t, jarCookie(t, client, target, refreshCookieName))
			for _, token := range []string{original, rotated} {
				assert.Equal(t, http.StatusUnauthorized, replayRefresh(t, client, target, token).StatusCode)
			}
			// A fresh middleware instance proves rejection comes from provider revocation too.
			other, otherClient := newTestServer(t, idp, "reader")
			assert.Equal(t, http.StatusUnauthorized, replayRefresh(t, otherClient, other.URL, rotated).StatusCode)
		})
	}
}

func TestLogoutCompletesWhenRevocationFails(t *testing.T) {
	idp := newFakeIDP(t)
	idp.RotateRefreshTokens()
	transport := idp.Client().Transport
	idp.Client().Transport = idpTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/revoke" {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: http.NoBody, Header: make(http.Header)}, nil
		}
		return transport.RoundTrip(r)
	})
	target, client := loggedIn(t, idp)
	original := jarCookie(t, client, target, refreshCookieName)
	expireSession(t, client, target)
	refreshed := browserGet(t, client, target+"/protected")
	require.NoError(t, refreshed.Body.Close())
	require.Equal(t, http.StatusOK, refreshed.StatusCode)
	token := jarCookie(t, client, target, refreshCookieName)
	res, err := client.Post(target+oidcauth.LogoutPath, "", nil)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	assert.Equal(t, http.StatusSeeOther, res.StatusCode)
	assert.Contains(t, res.Header.Get("Location"), idp.IssuerURL()+"/logout")
	assert.Empty(t, jarCookie(t, client, target, sessionCookieName))
	assert.Empty(t, jarCookie(t, client, target, refreshCookieName))
	assert.Equal(t, http.StatusUnauthorized, replayRefresh(t, client, target, token).StatusCode)
	assert.Equal(t, http.StatusUnauthorized, replayRefresh(t, client, target, original).StatusCode)
}

func TestRevocationDiscovery(t *testing.T) {
	for _, method := range []string{"missing-endpoint", "client_secret_post", "unsupported"} {
		t.Run(method, func(t *testing.T) {
			idp := newFakeIDP(t)
			idp.RotateRefreshTokens()
			transport := idp.Client().Transport
			idp.Client().Transport = idpTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/revoke" {
					copy := r.Clone(r.Context())
					var err error
					copy.Body, err = r.GetBody()
					if err != nil {
						return nil, err
					}
					defer func() { _ = copy.Body.Close() }()
					assert.Empty(t, copy.Header.Get("Authorization"))
					assert.Equal(t, testClientID, copy.PostFormValue("client_id"))
					assert.Equal(t, testClientSecret, copy.PostFormValue("client_secret"))
					assert.Equal(t, "refresh_token", copy.PostFormValue("token_type_hint"))
				}
				res, err := transport.RoundTrip(r)
				if err != nil || !strings.Contains(r.URL.Path, "openid-configuration") {
					return res, err
				}
				var discovery map[string]any
				if err := json.NewDecoder(res.Body).Decode(&discovery); err != nil {
					_ = res.Body.Close()
					return nil, err
				}
				_ = res.Body.Close()
				if method == "missing-endpoint" {
					delete(discovery, "revocation_endpoint")
				} else {
					discovery["revocation_endpoint_auth_methods_supported"] = []string{method}
				}
				body, err := json.Marshal(discovery)
				if err != nil {
					return nil, err
				}
				res.Body = io.NopCloser(strings.NewReader(string(body)))
				res.ContentLength = int64(len(body))
				res.Header.Del("Content-Length")
				return res, nil
			})
			target, client := loggedIn(t, idp)
			original := jarCookie(t, client, target, refreshCookieName)
			require.NotEmpty(t, original)
			expireSession(t, client, target)
			refreshed := browserGet(t, client, target+"/protected")
			require.NoError(t, refreshed.Body.Close())
			require.Equal(t, http.StatusOK, refreshed.StatusCode)
			assert.Equal(t, 1, idp.Refreshes())
			rotated := jarCookie(t, client, target, refreshCookieName)
			res, err := client.Post(target+oidcauth.LogoutPath, "", nil)
			require.NoError(t, err)
			require.NoError(t, res.Body.Close())
			assert.Equal(t, http.StatusSeeOther, res.StatusCode)
			assert.Empty(t, jarCookie(t, client, target, sessionCookieName))
			assert.Empty(t, jarCookie(t, client, target, refreshCookieName))
			assert.Equal(t, http.StatusUnauthorized, replayRefresh(t, client, target, original).StatusCode)
			assert.Equal(t, http.StatusUnauthorized, replayRefresh(t, client, target, rotated).StatusCode)
		})
	}
}

func TestRevocationDoesNotFollowRedirects(t *testing.T) {
	idp := newFakeIDP(t)
	transport := idp.Client().Transport
	var forwarded atomic.Bool
	idp.Client().Transport = idpTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/revoke" {
			return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": {idp.IssuerURL() + "/leak"}}, Body: http.NoBody}, nil
		}
		if r.URL.Path == "/leak" {
			forwarded.Store(true)
		}
		return transport.RoundTrip(r)
	})
	target, client := loggedIn(t, idp)
	res, err := client.Post(target+oidcauth.LogoutPath, "", nil)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	assert.Equal(t, http.StatusSeeOther, res.StatusCode)
	assert.False(t, forwarded.Load())
}
