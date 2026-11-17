package oidcauth //nolint:testpackage // Exercise the private coordinator with deterministic time and scheduling.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cego/go-lib/v2/logger/loggertest"
	"github.com/cego/go-lib/v2/renderer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestRefreshExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var f refreshes
		expiry := time.Now().Add(time.Second)
		var accepted int
		exchange := func(context.Context) (session, error) { return session{expiry: expiry}, nil }
		accept := func(session) { accepted++ }
		require.NoError(t, f.do(t.Context(), "token", exchange, accept))
		time.Sleep(2 * time.Second)
		require.Error(t, f.do(t.Context(), "token", exchange, accept))
		assert.Equal(t, 1, accepted)
	})
}

func TestRefreshWaitCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var f refreshes
		release := make(chan struct{})
		exchange := func(context.Context) (session, error) {
			<-release
			return session{expiry: time.Now().Add(time.Minute)}, nil
		}
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() {
			result <- f.do(ctx, "token", exchange, func(session) { t.Error("cancelled request accepted") })
		}()
		synctest.Wait()
		cancel()
		require.ErrorIs(t, <-result, context.Canceled)
		waiter, cancelWaiter := context.WithCancel(t.Context())
		go func() {
			result <- f.do(waiter, "token", exchange, func(session) { t.Error("cancelled waiter accepted") })
		}()
		synctest.Wait()
		cancelWaiter()
		require.ErrorIs(t, <-result, context.Canceled)
		close(release)
		require.NoError(t, f.do(t.Context(), "token", exchange, func(session) {}))
	})
}

func TestRefreshDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var f refreshes
		started := time.Now()
		err := f.do(t.Context(), "token", func(ctx context.Context) (session, error) {
			<-ctx.Done()
			return session{}, ctx.Err()
		}, func(session) { t.Error("timed out refresh accepted") })
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, tokenRequestTimeout, time.Since(started))
	})
}

func TestRefreshCacheLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var f refreshes
		var exchanges int
		rejected := errors.New("invalid grant")
		exchange := func(context.Context) (session, error) { exchanges++; return session{}, rejected }
		for i := 0; i < maxRefreshEntries; i++ {
			_ = f.do(t.Context(), fmt.Sprint(i), exchange, func(session) { t.Error("invalid token accepted") })
		}
		require.ErrorIs(t, f.do(t.Context(), "excess", exchange, func(session) {}), errRefreshBusy)
		assert.LessOrEqual(t, exchanges, maxRefreshEntries)
		assert.LessOrEqual(t, len(f.calls), maxRefreshEntries)
		time.Sleep(refreshLinger)
		require.ErrorIs(t, f.do(t.Context(), "after-expiry", exchange, func(session) {}), rejected)
	})
}

func TestLogoutInvalidatesRotatedAliases(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var f refreshes
		var exchanges int
		exchange := func(context.Context) (session, error) {
			exchanges++
			return session{refreshToken: "rotated", expiry: time.Now().Add(time.Minute)}, nil
		}
		require.NoError(t, f.do(t.Context(), "original", exchange, func(session) {}))
		require.NoError(t, f.do(t.Context(), "rotated", exchange, func(session) {}))
		tokens, err := f.invalidate(t.Context(), "rotated")
		require.NoError(t, err)
		assert.Equal(t, []string{"rotated"}, tokens)
		for _, token := range []string{"original", "rotated"} {
			require.Error(t, f.do(t.Context(), token, exchange, func(session) { t.Error("revoked session accepted") }))
		}
		assert.Equal(t, 1, exchanges)
	})
}

func TestLogoutDuringRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var f refreshes
		release := make(chan struct{})
		result := make(chan error, 1)
		go func() {
			result <- f.do(t.Context(), "original", func(context.Context) (session, error) {
				<-release
				return session{refreshToken: "rotated", expiry: time.Now().Add(time.Minute)}, nil
			}, func(session) { t.Error("logout restored a session") })
		}()
		synctest.Wait()
		var tokens []string
		var revokeErr error
		go func() { tokens, revokeErr = f.invalidate(t.Context(), "original") }()
		synctest.Wait()
		close(release)
		require.Error(t, <-result)
		synctest.Wait()
		require.NoError(t, revokeErr)
		assert.Equal(t, []string{"original", "rotated"}, tokens)
	})
}

func TestLogoutOfReturnedAliasDuringRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var f refreshes
		release := make(chan struct{})
		result := make(chan error, 1)
		exchange := func(context.Context) (session, error) {
			<-release
			return session{refreshToken: "rotated", expiry: time.Now().Add(time.Minute)}, nil
		}
		go func() {
			result <- f.do(t.Context(), "original", exchange, func(session) { t.Error("revoked alias accepted") })
		}()
		synctest.Wait()
		_, err := f.invalidate(t.Context(), "rotated")
		require.NoError(t, err)
		close(release)
		require.Error(t, <-result)
		require.Error(t, f.do(t.Context(), "rotated", exchange, func(session) { t.Error("revocation overwritten") }))
	})
}

type revokeTransport func(*http.Request) (*http.Response, error)

func (f revokeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLogoutRetryAfterRotationCacheExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fail := true
		var revoked []string
		l := loggertest.NewMock()
		o := &OidcAuth{
			logger: l, renderer: renderer.New(l),
			revocationURL: "https://example.com/revoke", tokenRequests: make(chan struct{}, maxTokenRequests),
			httpClient: &http.Client{Transport: revokeTransport(func(r *http.Request) (*http.Response, error) {
				token := r.PostFormValue("token")
				status := http.StatusOK
				if fail && token == "rotated" {
					status = http.StatusServiceUnavailable
				} else {
					revoked = append(revoked, token)
				}
				return &http.Response{StatusCode: status, Body: http.NoBody}, nil
			})},
		}
		require.NoError(t, o.refreshes.do(t.Context(), "original", func(context.Context) (session, error) {
			return session{refreshToken: "rotated", expiry: time.Now().Add(time.Minute)}, nil
		}, func(session) {}))
		logout := func(token string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodPost, LogoutPath, nil)
			r.AddCookie(&http.Cookie{Name: o.cookieName(refreshCookie), Value: token})
			w := httptest.NewRecorder()
			o.Logout(w, r)
			return w
		}
		first := logout("original")
		require.Equal(t, http.StatusServiceUnavailable, first.Code)
		res := first.Result()
		defer func() { _ = res.Body.Close() }()
		var retry string
		for _, cookie := range res.Cookies() {
			if cookie.Name == o.cookieName(refreshCookie) {
				retry = cookie.Value
			}
		}
		require.Equal(t, "rotated", retry)
		time.Sleep(2*tokenRequestTimeout + refreshLinger + time.Second)
		fail = false
		require.Equal(t, http.StatusSeeOther, logout(retry).Code)
		assert.Contains(t, revoked, "rotated")
	})
}

type blockedTokenTransport struct{}

func (blockedTokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return nil, r.Context().Err()
}

func TestRefreshConcurrencyLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		o := &OidcAuth{
			logger: loggertest.NewMock(), httpClient: &http.Client{Transport: blockedTokenTransport{}},
			revocationURL: "https://example.com/revoke", tokenRequests: make(chan struct{}, maxTokenRequests),
			oauth: oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: "https://example.com/token"}},
		}
		var wait sync.WaitGroup
		for i := 0; i < maxTokenRequests; i++ {
			wait.Go(func() {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.AddCookie(&http.Cookie{Name: o.cookieName(refreshCookie), Value: fmt.Sprint(i)})
				_, err := o.refreshSession(httptest.NewRecorder(), r)
				assert.ErrorIs(t, err, context.DeadlineExceeded)
			})
		}
		synctest.Wait()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: o.cookieName(refreshCookie), Value: "excess"})
		_, err := o.refreshSession(httptest.NewRecorder(), r)
		require.ErrorIs(t, err, errRefreshBusy)
		assert.Len(t, o.tokenRequests, maxTokenRequests)
		wait.Wait()
	})
}
