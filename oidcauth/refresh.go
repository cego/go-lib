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
	refreshLinger       = 10 * time.Second
	tokenRequestTimeout = 10 * time.Second
	maxTokenRequests    = 32
	maxRefreshEntries   = 1024
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

var errRefreshBusy = errors.New("too many token requests")

// refreshSession renews a browser session using a refresh token.
func (o *OidcAuth) refreshSession(w http.ResponseWriter, r *http.Request) (User, error) {
	if r.Header.Get(headers.Authorization) != "" {
		return User{}, errors.New("a bearer token is not refreshed")
	}

	cookie, err := r.Cookie(o.cookieName(refreshCookie))
	if err != nil || cookie.Value == "" || len(cookie.Value) > maxSessionCookieBytes {
		return User{}, errors.New("no usable refresh token")
	}

	var user User
	err = o.refreshes.do(r.Context(), cookie.Value, func(ctx context.Context) (session, error) {
		select {
		case o.tokenRequests <- struct{}{}:
			defer func() { <-o.tokenRequests }()
		default:
			return session{}, errRefreshBusy
		}
		ctx = coreoidc.ClientContext(ctx, o.httpClient)
		token, err := o.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: cookie.Value}).Token()
		if err != nil {
			return session{}, fmt.Errorf("exchanging refresh token: %w", err)
		}
		refreshed, _, err := o.sessionFrom(ctx, token)
		// Keep the rotated token available for logout even if ID token validation fails.
		refreshed.refreshToken = token.RefreshToken
		return refreshed, err
	}, func(refreshed session) {
		o.setSession(w, refreshed)
		user = refreshed.user
	})
	if err != nil {
		o.logger.Info("could not refresh the session", logger.GetSlogAttrFromError(err))
	}
	return user, err
}

// Both token hashes share a call so logout also invalidates requests using a rotated token.
type refreshes struct {
	mu      sync.Mutex
	calls   map[[sha256.Size]byte]*refreshCall
	running int
}

type refreshCall struct {
	done    chan struct{}
	session session
	err     error
	expires time.Time
	revoked bool
}

func (f *refreshes) prune() {
	for key, call := range f.calls {
		if !call.expires.IsZero() && !time.Now().Before(call.expires) {
			delete(f.calls, key)
		}
	}
	if f.calls == nil {
		f.calls = map[[sha256.Size]byte]*refreshCall{}
	}
}

func (f *refreshes) do(ctx context.Context, token string, exchange func(context.Context) (session, error), accept func(session)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := sha256.Sum256([]byte(token))
	f.mu.Lock()
	f.prune()
	call, found := f.calls[key]
	if !found {
		// Reserve one entry for the token returned by a rotating provider.
		if len(f.calls)+f.running+2 > maxRefreshEntries {
			f.mu.Unlock()
			return errRefreshBusy
		}
		call = &refreshCall{done: make(chan struct{})}
		f.calls[key] = call
		f.running++
		go func() {
			// A disconnected requester must not cancel another request's refresh.
			exchangeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tokenRequestTimeout)
			defer cancel()
			s, err := exchange(exchangeCtx)
			f.mu.Lock()
			defer f.mu.Unlock()
			f.running--
			call.session, call.err = s, err
			call.expires = time.Now().Add(refreshLinger)
			if err == nil && s.expiry.Before(call.expires) {
				call.expires = s.expiry
			}
			if s.refreshToken != "" {
				alias := sha256.Sum256([]byte(s.refreshToken))
				if existing := f.calls[alias]; existing != nil && existing != call {
					// Overlapping exchanges must not replace another call's revocation state.
					call.revoked = true
					existing.revoked = true
				} else {
					f.calls[alias] = call
				}
			}
			if call.revoked {
				call.expires = time.Now().Add(2*tokenRequestTimeout + refreshLinger)
			}
			close(call.done)
		}()
	}
	f.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-call.done:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if call.revoked {
		return errors.New("session revoked")
	}
	if call.err != nil {
		return call.err
	}
	if !time.Now().Before(call.session.expiry) || !time.Now().Before(call.expires) {
		return errors.New("refreshed session expired")
	}
	accept(call.session)
	return nil
}

func (f *refreshes) invalidate(ctx context.Context, token string) ([]string, error) {
	key := sha256.Sum256([]byte(token))
	f.mu.Lock()
	f.prune()
	call := f.calls[key]
	if call == nil {
		if len(f.calls)+f.running+1 > maxRefreshEntries {
			f.mu.Unlock()
			return nil, errRefreshBusy
		}
		call = &refreshCall{done: make(chan struct{}), expires: time.Now()}
		close(call.done)
		f.calls[key] = call
	}
	call.revoked = true
	if !call.expires.IsZero() {
		call.expires = time.Now().Add(2*tokenRequestTimeout + refreshLinger)
	}
	f.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.done:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	tokens := []string{token}
	if rotated := call.session.refreshToken; rotated != "" && rotated != token {
		tokens = append(tokens, rotated)
	}
	return tokens, nil
}
