package oidcauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/cego/go-lib/v2/headers"
	"github.com/cego/go-lib/v2/logger"
	"github.com/cego/go-lib/v2/renderer"
	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	LoginPath    = "/auth/login"
	CallbackPath = "/auth/callback"
	LogoutPath   = "/auth/logout"

	DefaultRolesClaim   = "client_roles"
	DefaultCookiePrefix = "oidcauth"

	transientCookieMaxAge = 10 * time.Minute

	loginExpiredMessage = "login expired, please try again"
	loginFailedMessage  = "login failed"

	maxSessionCookieBytes = 3800
)

type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	BaseURL      string
}

type User struct {
	Subject           string
	Email             string
	EmailVerified     bool
	Name              string
	GivenName         string
	FamilyName        string
	PreferredUsername string
	Roles             []string
}

func (u User) HasRole(role string) bool {
	return slices.Contains(u.Roles, role)
}

func (u User) HasAnyRole(roles ...string) bool {
	if len(roles) == 0 {
		return true
	}

	for _, role := range roles {
		if u.HasRole(role) {
			return true
		}
	}

	return false
}

type OptionFunc func(o *OidcAuth)

func WithHTTPClient(httpClient *http.Client) OptionFunc {
	return func(o *OidcAuth) {
		o.httpClient = httpClient
	}
}

func WithScopes(scopes ...string) OptionFunc {
	return func(o *OidcAuth) {
		o.scopes = scopes
		if !slices.Contains(o.scopes, coreoidc.ScopeOpenID) {
			o.scopes = append([]string{coreoidc.ScopeOpenID}, o.scopes...)
		}
	}
}

func WithRolesClaim(claim string) OptionFunc {
	return func(o *OidcAuth) {
		o.rolesClaim = claim
	}
}

func WithBearerAudience(audience string) OptionFunc {
	return func(o *OidcAuth) {
		o.bearerAudience = audience
	}
}

func WithCookiePrefix(prefix string) OptionFunc {
	return func(o *OidcAuth) {
		o.cookiePrefix = prefix
	}
}

type OidcAuth struct {
	logger         logger.Logger
	baseURL        string
	renderer       *renderer.Renderer
	oauth          oauth2.Config
	verifier       *coreoidc.IDTokenVerifier
	bearerVerifier *coreoidc.IDTokenVerifier
	bearerAudience string
	endSessionURL  string
	httpClient     *http.Client
	scopes         []string
	rolesClaim     string
	cookiePrefix   string
}

func New(ctx context.Context, l logger.Logger, cfg Config, opts ...OptionFunc) (*OidcAuth, error) {
	if err := requireSecureURL("issuer", cfg.Issuer); err != nil {
		return nil, err
	}
	if err := requireSecureURL("base url", cfg.BaseURL); err != nil {
		return nil, err
	}
	if cfg.ClientID == "" {
		return nil, errors.New("client id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("client secret is required")
	}

	o := &OidcAuth{
		logger:       l,
		renderer:     renderer.New(l),
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		scopes:       []string{coreoidc.ScopeOpenID, "profile", "email"},
		rolesClaim:   DefaultRolesClaim,
		cookiePrefix: DefaultCookiePrefix,
	}
	for _, opt := range opts {
		opt(o)
	}

	provider, err := coreoidc.NewProvider(coreoidc.ClientContext(ctx, o.httpClient), cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovering issuer %s: %w", cfg.Issuer, err)
	}

	var discovery struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
		JwksURI            string `json:"jwks_uri"`
	}
	if err := provider.Claims(&discovery); err != nil {
		return nil, fmt.Errorf("reading discovery document: %w", err)
	}

	for name, endpoint := range map[string]string{
		"authorization_endpoint": provider.Endpoint().AuthURL,
		"token_endpoint":         provider.Endpoint().TokenURL,
		"jwks_uri":               discovery.JwksURI,
		"end_session_endpoint":   discovery.EndSessionEndpoint,
	} {
		if endpoint == "" {
			continue
		}
		if err := requireSecureURL("discovered "+name, endpoint); err != nil {
			return nil, err
		}
	}

	o.baseURL = strings.TrimSuffix(cfg.BaseURL, "/")
	o.oauth = oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  o.baseURL + CallbackPath,
		Scopes:       o.scopes,
	}
	o.verifier = provider.Verifier(&coreoidc.Config{ClientID: cfg.ClientID})
	if o.bearerAudience == "" {
		o.bearerAudience = cfg.ClientID
	}
	o.bearerVerifier = provider.Verifier(&coreoidc.Config{ClientID: o.bearerAudience})
	o.endSessionURL = discovery.EndSessionEndpoint

	return o, nil
}

func (o *OidcAuth) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+LoginPath, o.Login)
	mux.HandleFunc("GET "+CallbackPath, o.Callback)
	mux.HandleFunc("POST "+LogoutPath, o.Logout)
}

func (o *OidcAuth) Handler(handler http.Handler, roles ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := o.userFromRequest(r)
		if err != nil {
			o.startAuthentication(w, r)
			return
		}

		if !user.HasAnyRole(roles...) {
			o.logger.Info("denied request without required role", "user", user.Email, "required", roles, "roles", user.Roles, "path", r.URL.Path)
			o.renderer.Text(w, http.StatusForbidden, "you do not hold any of the roles "+strings.Join(roles, ", "))
			return
		}

		handler.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
	})
}

func (o *OidcAuth) HandlerFunc(handlerFunc http.HandlerFunc, roles ...string) http.Handler {
	return o.Handler(handlerFunc, roles...)
}

func (o *OidcAuth) Middleware(roles ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return o.Handler(next, roles...)
	}
}

func (o *OidcAuth) startAuthentication(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", LoginPath)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if r.Header.Get(headers.Authorization) != "" || !strings.Contains(r.Header.Get("Accept"), "text/html") {
		o.renderer.Text(w, http.StatusUnauthorized, "authentication required")
		return
	}

	o.Login(w, r)
}

func (o *OidcAuth) Login(w http.ResponseWriter, r *http.Request) {
	state, err := randomString()
	if err != nil {
		o.renderer.Text(w, http.StatusInternalServerError, "could not start login")
		o.logger.Error("failed to generate state", "error", err)
		return
	}
	nonce, err := randomString()
	if err != nil {
		o.renderer.Text(w, http.StatusInternalServerError, "could not start login")
		o.logger.Error("failed to generate nonce", "error", err)
		return
	}

	verifier := oauth2.GenerateVerifier()
	o.setCookie(w, stateCookie, state, transientCookieMaxAge)
	o.setCookie(w, nonceCookie, nonce, transientCookieMaxAge)
	o.setCookie(w, verifierCookie, verifier, transientCookieMaxAge)
	o.setCookie(w, returnCookie, returnTarget(r), transientCookieMaxAge)

	http.Redirect(w, r, o.oauth.AuthCodeURL(state, coreoidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (o *OidcAuth) Callback(w http.ResponseWriter, r *http.Request) {
	state, err := r.Cookie(o.cookieName(stateCookie))
	if err != nil || state.Value == "" || state.Value != r.URL.Query().Get("state") {
		o.renderer.Text(w, http.StatusBadRequest, loginExpiredMessage)
		return
	}

	verifier, err := r.Cookie(o.cookieName(verifierCookie))
	if err != nil {
		o.renderer.Text(w, http.StatusBadRequest, loginExpiredMessage)
		return
	}

	token, err := o.oauth.Exchange(coreoidc.ClientContext(r.Context(), o.httpClient), r.URL.Query().Get("code"), oauth2.VerifierOption(verifier.Value))
	if err != nil {
		o.renderer.Text(w, http.StatusUnauthorized, loginFailedMessage)
		o.logger.Error("failed to exchange authorization code", "error", err)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		o.renderer.Text(w, http.StatusUnauthorized, loginFailedMessage)
		o.logger.Error("token response had no id_token")
		return
	}

	idToken, err := o.verifier.Verify(coreoidc.ClientContext(r.Context(), o.httpClient), rawIDToken)
	if err != nil {
		o.renderer.Text(w, http.StatusUnauthorized, loginFailedMessage)
		o.logger.Error("failed to verify id token", "error", err)
		return
	}

	nonce, err := r.Cookie(o.cookieName(nonceCookie))
	if err != nil || idToken.Nonce != nonce.Value {
		o.renderer.Text(w, http.StatusBadRequest, loginExpiredMessage)
		return
	}

	user, err := o.claimsToUser(idToken, true)
	if err != nil {
		o.renderer.Text(w, http.StatusUnauthorized, loginFailedMessage)
		o.logger.Error("failed to read id token claims", "error", err)
		return
	}

	if len(rawIDToken) > maxSessionCookieBytes {
		o.renderer.Text(w, http.StatusInternalServerError, loginFailedMessage)
		o.logger.Error("id token is too large to keep in a cookie", "bytes", len(rawIDToken), "limit", maxSessionCookieBytes)
		return
	}

	o.setCookie(w, sessionCookie, rawIDToken, time.Until(idToken.Expiry))
	o.clearCookie(w, stateCookie)
	o.clearCookie(w, nonceCookie)
	o.clearCookie(w, verifierCookie)

	target := "/"
	if returnTo, err := r.Cookie(o.cookieName(returnCookie)); err == nil {
		target = safeTarget(returnTo.Value)
	}
	o.clearCookie(w, returnCookie)

	o.logger.Info("logged in", "user", user.Email, "roles", user.Roles)
	http.Redirect(w, r, target, http.StatusFound)
}

func (o *OidcAuth) Logout(w http.ResponseWriter, r *http.Request) {
	o.clearCookie(w, sessionCookie)

	endSession, err := url.Parse(o.endSessionURL)
	if err != nil || o.endSessionURL == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	query := endSession.Query()
	query.Set("client_id", o.oauth.ClientID)
	query.Set("post_logout_redirect_uri", o.baseURL+"/")
	endSession.RawQuery = query.Encode()

	http.Redirect(w, r, endSession.String(), http.StatusSeeOther)
}

func (o *OidcAuth) userFromRequest(r *http.Request) (User, error) {
	ctx := coreoidc.ClientContext(r.Context(), o.httpClient)

	if authorization := r.Header.Get(headers.Authorization); authorization != "" {
		bearer, found := strings.CutPrefix(authorization, "Bearer ")
		if !found {
			return User{}, errors.New("authorization header is not a bearer token")
		}

		token, err := o.bearerVerifier.Verify(ctx, bearer)
		if err != nil {
			return User{}, fmt.Errorf("verifying bearer token: %w", err)
		}

		return o.claimsToUser(token, false)
	}

	cookie, err := r.Cookie(o.cookieName(sessionCookie))
	if err != nil {
		return User{}, errors.New("no session")
	}

	idToken, err := o.verifier.Verify(ctx, cookie.Value)
	if err != nil {
		return User{}, fmt.Errorf("verifying session: %w", err)
	}

	return o.claimsToUser(idToken, true)
}

func (o *OidcAuth) claimsToUser(idToken *coreoidc.IDToken, requireOurAuthorizedParty bool) (User, error) {
	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return User{}, err
	}

	if requireOurAuthorizedParty {
		if err := o.validateAuthorizedParty(idToken, claims); err != nil {
			return User{}, err
		}
	}
	if idToken.Subject == "" {
		return User{}, errors.New("token has no sub claim")
	}

	user := User{
		Subject:           idToken.Subject,
		Email:             stringFrom(claims, "email"),
		Name:              stringFrom(claims, "name"),
		GivenName:         stringFrom(claims, "given_name"),
		FamilyName:        stringFrom(claims, "family_name"),
		PreferredUsername: stringFrom(claims, "preferred_username"),
		Roles:             o.rolesFrom(claims),
	}
	user.EmailVerified, _ = claims["email_verified"].(bool)

	return user, nil
}

func (o *OidcAuth) validateAuthorizedParty(idToken *coreoidc.IDToken, claims map[string]any) error {
	authorizedParty := stringFrom(claims, "azp")
	if authorizedParty != "" && authorizedParty != o.oauth.ClientID {
		return fmt.Errorf("token authorized for %q, not %q", authorizedParty, o.oauth.ClientID)
	}
	if authorizedParty == "" && len(idToken.Audience) > 1 {
		return errors.New("token has several audiences and no azp claim")
	}

	return nil
}

func (o *OidcAuth) rolesFrom(claims map[string]any) []string {
	roles := stringsFrom(claims[o.rolesClaim])

	if resourceAccess, ok := claims["resource_access"].(map[string]any); ok {
		if ours, ok := resourceAccess[o.oauth.ClientID].(map[string]any); ok {
			roles = append(roles, stringsFrom(ours["roles"])...)
		}
	}

	return roles
}

func stringFrom(claims map[string]any, key string) string {
	value, _ := claims[key].(string)
	return value
}

func requireSecureURL(name, value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("%s must be an absolute url, got %q", name, value)
	}

	if parsed.Scheme == "https" || (parsed.Scheme == "http" && isLoopback(parsed.Hostname())) {
		return nil
	}

	return fmt.Errorf("%s must be https, got %q", name, value)
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func safeTarget(value string) string {
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.HasPrefix(value, `/\`) {
		return "/"
	}

	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" || isAuthPath(parsed.Path) {
		return "/"
	}

	return value
}

func stringsFrom(claim any) []string {
	values, ok := claim.([]any)
	if !ok {
		return nil
	}

	var strings []string
	for _, value := range values {
		if value, ok := value.(string); ok {
			strings = append(strings, value)
		}
	}

	return strings
}

func returnTarget(r *http.Request) string {
	if r.Method != http.MethodGet || isAuthPath(r.URL.Path) {
		return "/"
	}
	return r.URL.RequestURI()
}

func isAuthPath(path string) bool {
	return path == LoginPath || path == CallbackPath || path == LogoutPath
}

func randomString() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
