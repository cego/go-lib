// Package oidcclient obtains access tokens for service to service calls with
// the OAuth2 client credentials grant. It is the outbound counterpart to
// oidcauth: oidcauth verifies tokens a service receives, oidcclient mints the
// tokens a service sends.
package oidcclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// DefaultRefreshBefore is how long before its expiry a cached token is
// replaced, so a token handed to a caller does not expire in flight.
const DefaultRefreshBefore = 30 * time.Second

type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
}

type OptionFunc func(t *TokenSource)

// WithHTTPClient replaces the client used to reach the issuer. The default has
// a 10s timeout.
func WithHTTPClient(httpClient *http.Client) OptionFunc {
	return func(t *TokenSource) {
		t.httpClient = httpClient
	}
}

// WithScopes requests scopes beyond the ones the provider grants the client by
// default.
func WithScopes(scopes ...string) OptionFunc {
	return func(t *TokenSource) {
		t.config.Scopes = slices.Clone(scopes)
	}
}

// WithRefreshBefore overrides DefaultRefreshBefore. A value at or below zero
// keeps the default.
func WithRefreshBefore(refreshBefore time.Duration) OptionFunc {
	return func(t *TokenSource) {
		if refreshBefore > 0 {
			t.refreshBefore = refreshBefore
		}
	}
}

// TokenSource hands out access tokens for one client, caching each until it is
// close to expiry. It is safe for concurrent use, and concurrent callers share
// an in-flight request to the issuer.
type TokenSource struct {
	issuer        string
	httpClient    *http.Client
	refreshBefore time.Duration
	config        clientcredentials.Config

	mu       sync.Mutex
	tokenURL string
	token    *oauth2.Token
	inFlight *tokenFetch
}

type tokenFetch struct {
	done          chan struct{}
	token         string
	err           error
	ownerCanceled bool
}

// New validates the configuration. The issuer is not contacted until the first
// Token call, so a provider that is briefly unreachable does not stop a service
// from starting.
func New(cfg Config, opts ...OptionFunc) (*TokenSource, error) {
	if err := requireSecureURL("issuer", cfg.Issuer); err != nil {
		return nil, err
	}
	if cfg.ClientID == "" {
		return nil, errors.New("client id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("client secret is required")
	}

	t := &TokenSource{
		issuer:        cfg.Issuer,
		httpClient:    &http.Client{Timeout: 10 * time.Second},
		refreshBefore: DefaultRefreshBefore,
		config: clientcredentials.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
		},
	}
	for _, opt := range opts {
		opt(t)
	}

	return t, nil
}

// Token returns an access token for the client, reusing the cached one until it
// is within the refresh window of expiring.
func (t *TokenSource) Token(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		t.mu.Lock()
		if t.fresh() {
			token := t.token.AccessToken
			t.mu.Unlock()

			return token, nil
		}

		if inFlight := t.inFlight; inFlight != nil {
			t.mu.Unlock()

			select {
			case <-inFlight.done:
				if err := ctx.Err(); err != nil {
					return "", err
				}
				if inFlight.ownerCanceled {
					continue
				}

				return inFlight.token, inFlight.err
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}

		inFlight := &tokenFetch{done: make(chan struct{})}
		t.inFlight = inFlight
		tokenURL := t.tokenURL
		if tokenURL != "" {
			t.config.TokenURL = tokenURL
		}
		t.mu.Unlock()

		token, tokenURL, err := t.fetchToken(ctx, tokenURL)
		inFlight.token, inFlight.err = "", err
		if token != nil {
			inFlight.token = token.AccessToken
		}
		inFlight.ownerCanceled = contextCancellation(ctx, err)

		t.mu.Lock()
		if tokenURL != "" {
			t.tokenURL = tokenURL
			t.config.TokenURL = tokenURL
		}
		if err == nil {
			t.token = token
		}
		t.inFlight = nil
		close(inFlight.done)
		t.mu.Unlock()

		return inFlight.token, inFlight.err
	}
}

func (t *TokenSource) fetchToken(ctx context.Context, tokenURL string) (*oauth2.Token, string, error) {
	if tokenURL == "" {
		var err error
		tokenURL, err = t.discoverTokenURL(ctx)
		if err != nil {
			return nil, "", err
		}

		t.mu.Lock()
		t.config.TokenURL = tokenURL
		t.mu.Unlock()
	}

	token, err := t.config.Token(coreoidc.ClientContext(ctx, t.httpClient))
	if err != nil {
		return nil, tokenURL, fmt.Errorf("requesting access token for client %s: %w", t.config.ClientID, err)
	}
	if token.AccessToken == "" {
		return nil, tokenURL, fmt.Errorf("issuer %s returned an empty access token", t.issuer)
	}

	return token, tokenURL, nil
}

func contextCancellation(ctx context.Context, err error) bool {
	ctxErr := ctx.Err()

	return ctxErr != nil && errors.Is(err, ctxErr)
}

// HTTPClient returns a client that sets the bearer token on every request it
// sends. Its transport reads the token per request, so it keeps working across
// refreshes. Cross-origin redirects are rejected to avoid forwarding the token.
func (t *TokenSource) HTTPClient(base *http.Client) *http.Client {
	client := &http.Client{}
	if base != nil {
		*client = *base
	}

	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = &bearerTransport{tokenSource: t, base: transport}

	return client
}

func (t *TokenSource) fresh() bool {
	return t.token != nil &&
		t.token.AccessToken != "" &&
		(t.token.Expiry.IsZero() || time.Now().Add(t.refreshBefore).Before(t.token.Expiry))
}

func (t *TokenSource) discoverTokenURL(ctx context.Context) (string, error) {
	provider, err := coreoidc.NewProvider(coreoidc.ClientContext(ctx, t.httpClient), t.issuer)
	if err != nil {
		return "", fmt.Errorf("discovering issuer %s: %w", t.issuer, err)
	}

	tokenURL := provider.Endpoint().TokenURL
	if err := requireSecureURL("discovered token_endpoint", tokenURL); err != nil {
		return "", err
	}

	return tokenURL, nil
}

type bearerTransport struct {
	tokenSource *TokenSource
	base        http.RoundTripper
}

func (b *bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Response != nil {
		if request.Response.Request == nil || !sameOrigin(request.Response.Request.URL, request.URL) {
			return nil, errors.New("refusing to send bearer token on a cross-origin redirect")
		}
	}

	token, err := b.tokenSource.Token(request.Context())
	if err != nil {
		return nil, err
	}

	// RoundTrippers must not modify the request they are given.
	request = request.Clone(request.Context())
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := b.base.RoundTrip(request)
	if err != nil {
		return nil, fmt.Errorf("sending request to %s: %w", request.URL.Redacted(), err)
	}

	return response, nil
}

func requireSecureURL(name, rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("%s is required", name)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parsing %s %s: %w", name, rawURL, err)
	}
	if !parsed.IsAbs() || parsed.Host == "" || parsed.Hostname() == "" {
		return fmt.Errorf("%s %s must be an absolute URL with a host", name, rawURL)
	}
	if !strings.EqualFold(parsed.Scheme, "https") &&
		(!strings.EqualFold(parsed.Scheme, "http") || !isLoopback(parsed.Hostname())) {
		return fmt.Errorf("%s %s must use https", name, rawURL)
	}

	return nil
}

func isLoopback(host string) bool {
	return strings.EqualFold(host, "localhost") || host == "127.0.0.1" || host == "::1"
}

func sameOrigin(first, second *url.URL) bool {
	if first == nil || second == nil {
		return false
	}

	return strings.EqualFold(first.Scheme, second.Scheme) &&
		strings.EqualFold(first.Hostname(), second.Hostname()) &&
		effectivePort(first) == effectivePort(second)
}

func effectivePort(parsed *url.URL) string {
	if port := parsed.Port(); port != "" {
		return port
	}

	switch strings.ToLower(parsed.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}
