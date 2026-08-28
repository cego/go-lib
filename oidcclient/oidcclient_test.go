package oidcclient_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cego/go-lib/v2/oidcclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testClientID     = "test-client"
	testClientSecret = "test-secret"
)

type fakeIssuer struct {
	server *httptest.Server

	mu           sync.Mutex
	tokenCalls   int
	expiresIn    int
	accessToken  string
	tokenStatus  int
	lastFormData map[string][]string
	tokenStarted chan<- struct{}
	tokenRelease <-chan struct{}
}

type notifyingContext struct {
	context.Context
	called chan<- struct{}
	once   sync.Once
}

type tokenResult struct {
	token string
	err   error
}

func (c *notifyingContext) Done() <-chan struct{} {
	c.once.Do(func() { c.called <- struct{}{} })

	return c.Context.Done()
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()

	issuer := &fakeIssuer{expiresIn: 300, accessToken: "token-1", tokenStatus: http.StatusOK}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer.server.URL,
			"authorization_endpoint": issuer.server.URL + "/auth",
			"token_endpoint":         issuer.server.URL + "/token",
			"jwks_uri":               issuer.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		issuer.mu.Lock()
		issuer.tokenCalls++
		calls := issuer.tokenCalls
		status := issuer.tokenStatus
		expiresIn := issuer.expiresIn
		issuer.lastFormData = r.Form
		tokenStarted := issuer.tokenStarted
		tokenRelease := issuer.tokenRelease
		issuer.mu.Unlock()
		if tokenStarted != nil {
			select {
			case tokenStarted <- struct{}{}:
			default:
			}
			<-tokenRelease
		}

		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("token-%d", calls),
			"token_type":   "Bearer",
			"expires_in":   expiresIn,
		})
	})

	issuer.server = httptest.NewTLSServer(mux)
	t.Cleanup(issuer.server.Close)

	return issuer
}

func (f *fakeIssuer) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.tokenCalls
}

func (f *fakeIssuer) form() map[string][]string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.lastFormData
}

func (f *fakeIssuer) setExpiresIn(seconds int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.expiresIn = seconds
}

func (f *fakeIssuer) setTokenStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.tokenStatus = status
}

func (f *fakeIssuer) blockTokenRequests() (<-chan struct{}, func()) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})

	f.mu.Lock()
	f.tokenStarted = started
	f.tokenRelease = release
	f.mu.Unlock()

	return started, func() { close(release) }
}

func newTestTokenSource(t *testing.T, issuer *fakeIssuer, opts ...oidcclient.OptionFunc) *oidcclient.TokenSource {
	t.Helper()

	tokenSource, err := oidcclient.New(oidcclient.Config{
		Issuer:       issuer.server.URL,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
	}, append([]oidcclient.OptionFunc{oidcclient.WithHTTPClient(issuer.server.Client())}, opts...)...)
	require.NoError(t, err)

	return tokenSource
}

func TestNewRejectsIncompleteConfig(t *testing.T) {
	tests := []struct {
		name   string
		config oidcclient.Config
		errors string
	}{
		{
			name:   "missing issuer",
			config: oidcclient.Config{ClientID: testClientID, ClientSecret: testClientSecret},
			errors: "issuer is required",
		},
		{
			name:   "insecure issuer",
			config: oidcclient.Config{Issuer: "http://issuer.example.com", ClientID: testClientID, ClientSecret: testClientSecret},
			errors: "must use https",
		},
		{
			name:   "issuer without host",
			config: oidcclient.Config{Issuer: "https:///issuer", ClientID: testClientID, ClientSecret: testClientSecret},
			errors: "must be an absolute URL with a host",
		},
		{
			name:   "malformed issuer",
			config: oidcclient.Config{Issuer: "https://[::1", ClientID: testClientID, ClientSecret: testClientSecret},
			errors: "parsing issuer",
		},
		{
			name:   "ftp loopback issuer",
			config: oidcclient.Config{Issuer: "ftp://127.0.0.1", ClientID: testClientID, ClientSecret: testClientSecret},
			errors: "must use https",
		},
		{
			name:   "missing client id",
			config: oidcclient.Config{Issuer: "https://issuer.example.com", ClientSecret: testClientSecret},
			errors: "client id is required",
		},
		{
			name:   "missing client secret",
			config: oidcclient.Config{Issuer: "https://issuer.example.com", ClientID: testClientID},
			errors: "client secret is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenSource, err := oidcclient.New(tt.config)

			require.Error(t, err)
			assert.Nil(t, tokenSource)
			assert.ErrorContains(t, err, tt.errors)
		})
	}
}

func TestNewAcceptsLoopbackHTTP(t *testing.T) {
	for _, issuer := range []string{"http://localhost", "http://127.0.0.1", "http://[::1]"} {
		t.Run(issuer, func(t *testing.T) {
			tokenSource, err := oidcclient.New(oidcclient.Config{
				Issuer:       issuer,
				ClientID:     testClientID,
				ClientSecret: testClientSecret,
			})

			require.NoError(t, err)
			assert.NotNil(t, tokenSource)
		})
	}
}

func TestNewDoesNotContactTheIssuer(t *testing.T) {
	issuer := newFakeIssuer(t)

	newTestTokenSource(t, issuer)

	assert.Equal(t, 0, issuer.calls())
}

func TestTokenSendsTheClientCredentialsGrant(t *testing.T) {
	issuer := newFakeIssuer(t)
	tokenSource := newTestTokenSource(t, issuer)

	token, err := tokenSource.Token(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "token-1", token)
	assert.Equal(t, []string{"client_credentials"}, issuer.form()["grant_type"])
}

func TestTokenRequestsTheConfiguredScopes(t *testing.T) {
	issuer := newFakeIssuer(t)
	tokenSource := newTestTokenSource(t, issuer, oidcclient.WithScopes("profile", "email"))

	_, err := tokenSource.Token(context.Background())

	require.NoError(t, err)
	assert.Equal(t, []string{"profile email"}, issuer.form()["scope"])
}

func TestTokenReusesACachedToken(t *testing.T) {
	issuer := newFakeIssuer(t)
	tokenSource := newTestTokenSource(t, issuer)

	first, err := tokenSource.Token(context.Background())
	require.NoError(t, err)

	second, err := tokenSource.Token(context.Background())
	require.NoError(t, err)

	assert.Equal(t, first, second)
	assert.Equal(t, 1, issuer.calls())
}

func TestTokenReplacesATokenCloseToExpiry(t *testing.T) {
	issuer := newFakeIssuer(t)
	// Every token is already inside the refresh window when it is handed out.
	issuer.setExpiresIn(10)
	tokenSource := newTestTokenSource(t, issuer, oidcclient.WithRefreshBefore(30*time.Second))

	first, err := tokenSource.Token(context.Background())
	require.NoError(t, err)

	second, err := tokenSource.Token(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "token-1", first)
	assert.Equal(t, "token-2", second)
	assert.Equal(t, 2, issuer.calls())
}

func TestTokenFetchesOnceForConcurrentCallers(t *testing.T) {
	issuer := newFakeIssuer(t)
	tokenSource := newTestTokenSource(t, issuer)

	var wg sync.WaitGroup
	tokens := make([]string, 8)
	for i := range tokens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := tokenSource.Token(context.Background())
			assert.NoError(t, err)
			tokens[i] = token
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, issuer.calls())
	for _, token := range tokens {
		assert.Equal(t, "token-1", token)
	}
}

func TestTokenSharesAnIssuerFailureForConcurrentCallers(t *testing.T) {
	issuer := newFakeIssuer(t)
	issuer.setTokenStatus(http.StatusInternalServerError)
	started, release := issuer.blockTokenRequests()
	tokenSource := newTestTokenSource(t, issuer)

	ownerResult := make(chan tokenResult, 1)
	go func() {
		token, err := tokenSource.Token(context.Background())
		ownerResult <- tokenResult{token: token, err: err}
	}()
	<-started

	const waiterCount = 7
	results := make(chan tokenResult, waiterCount)
	ready := make(chan struct{}, waiterCount)
	for range waiterCount {
		ctx := &notifyingContext{Context: context.Background(), called: ready}
		go func() {
			token, err := tokenSource.Token(ctx)
			results <- tokenResult{token: token, err: err}
		}()
	}
	for range waiterCount {
		<-ready
	}
	release()

	owner := <-ownerResult
	require.Error(t, owner.err)
	assert.Empty(t, owner.token)
	for range waiterCount {
		waiter := <-results
		assert.Empty(t, waiter.token)
		assert.Same(t, owner.err, waiter.err)
	}
	// clientcredentials probes both auth styles on the first issuer failure.
	assert.Equal(t, 2, issuer.calls())
}

func TestTokenWaiterCanCancelWhileFetchIsInProgress(t *testing.T) {
	issuer := newFakeIssuer(t)
	started, release := issuer.blockTokenRequests()
	tokenSource := newTestTokenSource(t, issuer)

	ownerResult := make(chan error, 1)
	go func() {
		_, err := tokenSource.Token(context.Background())
		ownerResult <- err
	}()
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	waiterStarted := make(chan struct{}, 1)
	notifyingCtx := &notifyingContext{Context: ctx, called: waiterStarted}
	waiterResult := make(chan error, 1)
	go func() {
		_, err := tokenSource.Token(notifyingCtx)
		waiterResult <- err
	}()
	<-waiterStarted
	cancel()

	select {
	case err := <-waiterResult:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("canceled waiter did not return")
	}

	release()
	require.NoError(t, <-ownerResult)
}

func TestCanceledOwnerDoesNotPoisonLiveWaiter(t *testing.T) {
	issuer := newFakeIssuer(t)
	started, release := issuer.blockTokenRequests()
	tokenSource := newTestTokenSource(t, issuer)

	ownerCtx, cancelOwner := context.WithCancel(context.Background())
	ownerResult := make(chan error, 1)
	go func() {
		_, err := tokenSource.Token(ownerCtx)
		ownerResult <- err
	}()
	<-started

	waiterStarted := make(chan struct{}, 1)
	waiterCtx := &notifyingContext{Context: context.Background(), called: waiterStarted}
	waiterResult := make(chan tokenResult, 1)
	go func() {
		token, err := tokenSource.Token(waiterCtx)
		waiterResult <- tokenResult{token: token, err: err}
	}()
	<-waiterStarted

	cancelOwner()
	require.ErrorIs(t, <-ownerResult, context.Canceled)
	release()

	waiter := <-waiterResult
	require.NoError(t, waiter.err)
	assert.Equal(t, "token-2", waiter.token)
}

func TestTokenWrapsAnIssuerError(t *testing.T) {
	issuer := newFakeIssuer(t)
	issuer.setTokenStatus(http.StatusUnauthorized)
	tokenSource := newTestTokenSource(t, issuer)

	token, err := tokenSource.Token(context.Background())

	require.Error(t, err)
	assert.Empty(t, token)
	assert.ErrorContains(t, err, "requesting access token for client "+testClientID)
}

func TestTokenReportsAnUnreachableIssuer(t *testing.T) {
	tokenSource, err := oidcclient.New(oidcclient.Config{
		Issuer:       "https://127.0.0.1:1/realms/test",
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
	}, oidcclient.WithHTTPClient(&http.Client{Timeout: time.Second}))
	require.NoError(t, err)

	token, err := tokenSource.Token(context.Background())

	require.Error(t, err)
	assert.Empty(t, token)
	assert.ErrorContains(t, err, "discovering issuer")
}

func TestHTTPClientSetsTheBearerToken(t *testing.T) {
	issuer := newFakeIssuer(t)
	tokenSource := newTestTokenSource(t, issuer)

	var authorization atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		authorization.Store(r.Header.Get("Authorization"))
	}))
	t.Cleanup(upstream.Close)

	response, err := tokenSource.HTTPClient(nil).Get(upstream.URL)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())

	assert.Equal(t, "Bearer token-1", authorization.Load())
}

func TestHTTPClientFollowsSameOriginRedirects(t *testing.T) {
	issuer := newFakeIssuer(t)
	tokenSource := newTestTokenSource(t, issuer)

	var authorization atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusFound)
	})
	mux.HandleFunc("/target", func(_ http.ResponseWriter, r *http.Request) {
		authorization.Store(r.Header.Get("Authorization"))
	})
	upstream := httptest.NewServer(mux)
	t.Cleanup(upstream.Close)

	response, err := tokenSource.HTTPClient(nil).Get(upstream.URL + "/start")
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())

	assert.Equal(t, "Bearer token-1", authorization.Load())
}

func TestHTTPClientRejectsCrossOriginRedirects(t *testing.T) {
	issuer := newFakeIssuer(t)
	tokenSource := newTestTokenSource(t, issuer)

	var targetCalls atomic.Int32
	var targetAuthorization atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		targetAuthorization.Store(r.Header.Get("Authorization"))
	}))
	t.Cleanup(target.Close)

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	_, err := tokenSource.HTTPClient(nil).Get(redirector.URL)

	require.Error(t, err)
	assert.Equal(t, int32(0), targetCalls.Load())
	assert.Nil(t, targetAuthorization.Load())
}

func TestHTTPClientFailsWhenNoTokenCanBeMinted(t *testing.T) {
	issuer := newFakeIssuer(t)
	issuer.setTokenStatus(http.StatusUnauthorized)
	tokenSource := newTestTokenSource(t, issuer)

	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(upstream.Close)

	_, err := tokenSource.HTTPClient(nil).Get(upstream.URL)

	require.Error(t, err)
	assert.ErrorContains(t, err, "requesting access token")
}
