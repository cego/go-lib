package oidcauth_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

const (
	testClientID     = "test-client"
	testClientSecret = "test-secret"
)

type fakeIDP struct {
	server *httptest.Server
	priv   *rsa.PrivateKey
	kid    string

	mu         sync.Mutex
	pending    map[string]map[string]any
	challenges map[string]string
	nextUser   map[string]any
	redirects  map[string]string
	expiry     time.Duration
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	idp := &fakeIDP{
		priv:       priv,
		kid:        "test-key",
		pending:    map[string]map[string]any{},
		challenges: map[string]string{},
		redirects:  map[string]string{},
		expiry:     5 * time.Minute,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", idp.handleDiscovery)
	mux.HandleFunc("/jwks", idp.handleJWKS)
	mux.HandleFunc("/auth", idp.handleAuthorize)
	mux.HandleFunc("/token", idp.handleToken)
	idp.server = httptest.NewTLSServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (idp *fakeIDP) IssuerURL() string { return idp.server.URL }

func (idp *fakeIDP) Client() *http.Client { return idp.server.Client() }

func (idp *fakeIDP) AllowRedirectURI(uri string) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.redirects[uri] = uri
}

func (idp *fakeIDP) LoginAs(claims map[string]any) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.nextUser = claims
}

func (idp *fakeIDP) MintAccessToken(t *testing.T, audience string, claims map[string]any) string {
	t.Helper()
	all := idp.idClaims(claims)
	all["aud"] = audience
	all["azp"] = "some-cli-client"
	token, err := idp.signJWT(all)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return token
}

func (idp *fakeIDP) MintIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	token, err := idp.signJWT(idp.idClaims(claims))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return token
}

func (idp *fakeIDP) idClaims(userClaims map[string]any) map[string]any {
	now := time.Now()
	claims := map[string]any{
		"iss": idp.server.URL,
		"aud": testClientID,
		"sub": "test-subject",
		"iat": now.Unix(),
		"exp": now.Add(idp.expiry).Unix(),
	}
	maps.Copy(claims, userClaims)
	return claims
}

func (idp *fakeIDP) signJWT(claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": idp.kid})
	body, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(header) + "." + enc.EncodeToString(body)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.priv, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + enc.EncodeToString(sig), nil
}

func (idp *fakeIDP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	u := idp.server.URL
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                u,
		"authorization_endpoint":                u + "/auth",
		"token_endpoint":                        u + "/token",
		"end_session_endpoint":                  u + "/logout",
		"jwks_uri":                              u + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	})
}

func (idp *fakeIDP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	pub := idp.priv.PublicKey
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": idp.kid,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

func (idp *fakeIDP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	idp.mu.Lock()
	redirectURI, registered := idp.redirects[r.URL.Query().Get("redirect_uri")]
	idp.mu.Unlock()
	if !registered {
		http.Error(w, "redirect_uri is not registered for this client", http.StatusBadRequest)
		return
	}
	challenge := r.URL.Query().Get("code_challenge")
	if challenge == "" {
		http.Error(w, "missing code_challenge", http.StatusBadRequest)
		return
	}
	if method := r.URL.Query().Get("code_challenge_method"); method != "S256" {
		http.Error(w, "code_challenge_method must be S256, got "+method, http.StatusBadRequest)
		return
	}

	idp.mu.Lock()
	user := idp.nextUser
	idp.nextUser = nil
	idp.mu.Unlock()
	if user == nil {
		http.Error(w, "fakeIDP: /auth called with no LoginAs primed", http.StatusBadRequest)
		return
	}

	claims := map[string]any{}
	maps.Copy(claims, user)
	if nonce := r.URL.Query().Get("nonce"); nonce != "" {
		claims["nonce"] = nonce
	}

	code, err := randomCode()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idp.mu.Lock()
	idp.pending[code] = claims
	idp.challenges[code] = challenge
	idp.mu.Unlock()

	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	query := target.Query()
	query.Set("code", code)
	query.Set("state", r.URL.Query().Get("state"))
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (idp *fakeIDP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID, clientSecret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	if clientID != testClientID || clientSecret != testClientSecret {
		http.Error(w, "invalid client", http.StatusUnauthorized)
		return
	}

	code := r.PostFormValue("code")
	idp.mu.Lock()
	userClaims, found := idp.pending[code]
	challenge := idp.challenges[code]
	delete(idp.pending, code)
	delete(idp.challenges, code)
	idp.mu.Unlock()
	if !found {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}

	sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
		http.Error(w, "PKCE verifier does not match challenge", http.StatusBadRequest)
		return
	}

	idToken, err := idp.signJWT(idp.idClaims(userClaims))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "not-used-by-oidcauth",
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   int(idp.expiry.Seconds()),
	})
}

func randomCode() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
