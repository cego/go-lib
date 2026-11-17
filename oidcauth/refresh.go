package oidcauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/cego/go-lib/v2/headers"
	"github.com/cego/go-lib/v2/logger"
	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	// defaultRefreshCookieMaxAge is how long the refresh cookie is kept when the provider does not say how long its token lasts.
	defaultRefreshCookieMaxAge = 24 * time.Hour

	// refreshLinger is how long the outcome of a refresh answers requests that still hold the token it used.
	refreshLinger = 10 * time.Second
)

// session is what a login or a refresh yields: the user, and the tokens kept in cookies.
type session struct {
	user          User
	rawIDToken    string
	expiry        time.Time
	refreshToken  string
	refreshMaxAge time.Duration
}

// sessionFrom verifies the id token of a token response. Login checks the nonce on what it returns; a refresh has none.
func (o *OidcAuth) sessionFrom(ctx context.Context, token *oauth2.Token) (session, *coreoidc.IDToken, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return session{}, nil, errors.New("token response had no id_token")
	}

	idToken, err := o.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return session{}, nil, fmt.Errorf("verifying id token: %w", err)
	}

	user, err := o.claimsToUser(idToken, true)
	if err != nil {
		return session{}, nil, fmt.Errorf("reading id token claims: %w", err)
	}

	if len(rawIDToken) > maxSessionCookieBytes {
		return session{}, nil, fmt.Errorf("id token of %d bytes is too large to keep in a cookie, the limit is %d", len(rawIDToken), maxSessionCookieBytes)
	}

	refreshMaxAge := defaultRefreshCookieMaxAge
	if seconds, ok := token.Extra("refresh_expires_in").(float64); ok && seconds > 0 {
		refreshMaxAge = time.Duration(seconds) * time.Second
	}

	return session{
		user:          user,
		rawIDToken:    rawIDToken,
		expiry:        idToken.Expiry,
		refreshToken:  token.RefreshToken,
		refreshMaxAge: refreshMaxAge,
	}, idToken, nil
}

func (o *OidcAuth) setSession(w http.ResponseWriter, s session) {
	o.setCookie(w, sessionCookie, s.rawIDToken, time.Until(s.expiry))

	if s.refreshToken == "" || len(s.refreshToken) > maxSessionCookieBytes {
		o.clearCookie(w, refreshCookie)
		return
	}
	o.setCookie(w, refreshCookie, s.refreshToken, s.refreshMaxAge)
}

// refreshSession renews the session of a browser whose id token ran out, when it holds a refresh token the provider still honours.
func (o *OidcAuth) refreshSession(w http.ResponseWriter, r *http.Request) (User, error) {
	if r.Header.Get(headers.Authorization) != "" {
		return User{}, errors.New("a bearer token is not refreshed")
	}

	cookie, err := r.Cookie(o.cookieName(refreshCookie))
	if err != nil || cookie.Value == "" {
		return User{}, errors.New("no refresh token")
	}

	// A request that goes away must not fail the others waiting on the same refresh.
	ctx := coreoidc.ClientContext(context.WithoutCancel(r.Context()), o.httpClient)
	refreshed, err := o.refreshes.do(cookie.Value, func() (session, error) {
		token, err := o.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: cookie.Value}).Token()
		if err != nil {
			return session{}, fmt.Errorf("exchanging refresh token: %w", err)
		}

		refreshed, _, err := o.sessionFrom(ctx, token)

		return refreshed, err
	})
	if err != nil {
		o.logger.Info("could not refresh the session", logger.GetSlogAttrFromError(err))
		o.clearCookie(w, refreshCookie)
		return User{}, err
	}

	o.setSession(w, refreshed)

	return refreshed.user, nil
}

// refreshes exchanges a refresh token once, and gives every request that arrives holding it the same outcome.
// A page often sends several requests at once, and a provider that rotates refresh tokens only honours the first.
type refreshes struct {
	mu    sync.Mutex
	calls map[[sha256.Size]byte]*refreshCall
}

type refreshCall struct {
	done    chan struct{}
	session session
	err     error
}

func (f *refreshes) do(refreshToken string, exchange func() (session, error)) (session, error) {
	key := sha256.Sum256([]byte(refreshToken))

	f.mu.Lock()
	if f.calls == nil {
		f.calls = map[[sha256.Size]byte]*refreshCall{}
	}
	call, found := f.calls[key]
	if !found {
		call = &refreshCall{done: make(chan struct{})}
		f.calls[key] = call
	}
	f.mu.Unlock()

	if found {
		<-call.done
		return call.session, call.err
	}

	call.session, call.err = exchange()
	close(call.done)
	time.AfterFunc(refreshLinger, func() {
		f.mu.Lock()
		delete(f.calls, key)
		f.mu.Unlock()
	})

	return call.session, call.err
}
