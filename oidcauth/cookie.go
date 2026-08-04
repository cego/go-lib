package oidcauth

import (
	"context"
	"net/http"
	"time"
)

const (
	sessionCookie  = "session"
	stateCookie    = "state"
	nonceCookie    = "nonce"
	verifierCookie = "verifier"
	returnCookie   = "return"
)

func (o *OidcAuth) cookieName(name string) string {
	return "__Host-" + o.cookiePrefix + "_" + name
}

func (o *OidcAuth) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     o.cookieName(name),
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (o *OidcAuth) clearCookie(w http.ResponseWriter, name string) {
	o.setCookie(w, name, "", -time.Second)
}

type contextKey struct{}

func withUser(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, contextKey{}, user)
}

func UserFromContext(ctx context.Context) User {
	user, ok := ctx.Value(contextKey{}).(User)
	if !ok {
		return User{}
	}
	return user
}
