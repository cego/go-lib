package oidcauth_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cego/go-lib/v2/logger"
	"github.com/cego/go-lib/v2/oidcauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func browserGet(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	request.Header.Set("Accept", "text/html")

	response, err := client.Do(request)
	require.NoError(t, err)

	return response
}

func newTestServer(t *testing.T, idp *fakeIDP, role string, opts ...oidcauth.OptionFunc) (*httptest.Server, *http.Client) {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	idp.AllowRedirectURI(server.URL + oidcauth.CallbackPath)

	auth, err := oidcauth.New(context.Background(), logger.NewMock(), oidcauth.Config{
		Issuer:       idp.IssuerURL(),
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		BaseURL:      server.URL,
	}, append([]oidcauth.OptionFunc{oidcauth.WithHTTPClient(idp.Client())}, opts...)...)
	require.NoError(t, err)

	auth.Register(mux)
	handler := func(w http.ResponseWriter, r *http.Request) {
		user := oidcauth.UserFromContext(r.Context())
		_, _ = w.Write([]byte(user.Email + " " + user.Subject))
	}

	var protected http.Handler
	if role == "" {
		protected = auth.HandlerFunc(handler)
	} else {
		protected = auth.HandlerFunc(handler, role)
	}
	mux.Handle("GET /protected", protected)
	mux.Handle("POST /protected", protected)
	mux.Handle("GET /names", auth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := oidcauth.UserFromContext(r.Context())
		_, _ = w.Write([]byte(user.GivenName + " " + user.FamilyName + " " + user.PreferredUsername))
	}, "reader"))

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	client := server.Client()
	client.Jar = jar

	return server, client
}

func TestOidcAuth(t *testing.T) {
	t.Run("a user with the role completes the flow and reaches the handler", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, client := newTestServer(t, idp, "reader")
		idp.LoginAs(map[string]any{"email": "mjn@cego.dk", "name": "Mads", "client_roles": []any{"reader"}})

		response := browserGet(t, client, server.URL+"/protected")
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusOK, response.StatusCode)
		body := make([]byte, 64)
		n, _ := response.Body.Read(body)
		assert.Contains(t, string(body[:n]), "mjn@cego.dk")
	})

	t.Run("a user without the role is refused", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, client := newTestServer(t, idp, "process-admin")
		idp.LoginAs(map[string]any{"email": "lejo@cego.dk", "client_roles": []any{"reader"}})

		response := browserGet(t, client, server.URL+"/protected")
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusForbidden, response.StatusCode)
	})

	t.Run("no session redirects to the provider", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, _ := newTestServer(t, idp, "reader")
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		response := browserGet(t, client, server.URL+"/protected")
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusFound, response.StatusCode)
		location, err := url.Parse(response.Header.Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, idp.IssuerURL()+"/auth", location.Scheme+"://"+location.Host+location.Path)
		assert.Equal(t, testClientID, location.Query().Get("client_id"))
		assert.Equal(t, "S256", location.Query().Get("code_challenge_method"))
		assert.NotEmpty(t, location.Query().Get("state"))
		assert.NotEmpty(t, location.Query().Get("nonce"))
	})

	t.Run("an htmx request is told to redirect instead of being sent to the provider", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, _ := newTestServer(t, idp, "reader")
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		request, err := http.NewRequest(http.MethodGet, server.URL+"/protected", nil)
		require.NoError(t, err)
		request.Header.Set("HX-Request", "true")

		response, err := client.Do(request)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
		assert.Equal(t, oidcauth.LoginPath, response.Header.Get("HX-Redirect"))
	})

	t.Run("a forged session cookie is not trusted", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, _ := newTestServer(t, idp, "reader")
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		request, err := http.NewRequest(http.MethodGet, server.URL+"/protected", nil)
		require.NoError(t, err)
		request.Header.Set("Accept", "text/html")
		request.AddCookie(&http.Cookie{Name: "__Host-oidcauth_session", Value: "not.a.jwt"})

		response, err := client.Do(request)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusFound, response.StatusCode)
	})

	t.Run("a token signed for another client is not trusted", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, _ := newTestServer(t, idp, "reader")
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		request, err := http.NewRequest(http.MethodGet, server.URL+"/protected", nil)
		require.NoError(t, err)
		request.Header.Set("Accept", "text/html")
		request.AddCookie(&http.Cookie{
			Name:  "__Host-oidcauth_session",
			Value: idp.MintIDToken(t, map[string]any{"aud": "some-other-client", "client_roles": []any{"reader"}}),
		})

		response, err := client.Do(request)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusFound, response.StatusCode)
	})

	t.Run("callback without the state cookie is rejected", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, _ := newTestServer(t, idp, "reader")

		response, err := server.Client().Get(server.URL + oidcauth.CallbackPath + "?code=whatever&state=whatever")
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	})

	t.Run("roles can be read from another claim", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, client := newTestServer(t, idp, "reader", oidcauth.WithRolesClaim("realm_roles"))
		idp.LoginAs(map[string]any{"email": "mjn@cego.dk", "realm_roles": []any{"reader"}})

		response := browserGet(t, client, server.URL+"/protected")
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("logout clears the session and ends it at the provider", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, _ := newTestServer(t, idp, "reader")
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		response, err := client.Post(server.URL+oidcauth.LogoutPath, "", nil)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusSeeOther, response.StatusCode)
		assert.Contains(t, response.Header.Get("Location"), idp.IssuerURL()+"/logout")
		assert.Contains(t, response.Header.Get("Set-Cookie"), "oidcauth_session=;")
	})

	t.Run("the options are applied", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, _ := newTestServer(t, idp, "reader",
			oidcauth.WithHTTPClient(idp.Client()),
			oidcauth.WithScopes("openid", "email"),
			oidcauth.WithCookiePrefix("myservice"),
		)
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		response := browserGet(t, client, server.URL+"/protected")
		defer func() { _ = response.Body.Close() }()

		location, err := url.Parse(response.Header.Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "openid email", location.Query().Get("scope"))
		assert.NotEmpty(t, cookieValue(t, response, "__Host-myservice_state"))
	})

	t.Run("the visited url is returned to after login", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, client := newTestServer(t, idp, "reader")
		idp.LoginAs(map[string]any{"email": "mjn@cego.dk", "client_roles": []any{"reader"}})

		response := browserGet(t, client, server.URL+"/protected?sort=time")
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.Equal(t, "/protected?sort=time", response.Request.URL.RequestURI())
	})

	t.Run("a callback with an unusable code fails the login", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, client := newTestServer(t, idp, "reader")
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		started := browserGet(t, client, server.URL+"/protected")
		_ = started.Body.Close()
		location, err := url.Parse(started.Header.Get("Location"))
		require.NoError(t, err)

		response, err := client.Get(server.URL + oidcauth.CallbackPath + "?code=not-a-real-code&state=" + location.Query().Get("state"))
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
	})

	t.Run("a post is returned to the root after login", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, client := newTestServer(t, idp, "reader")
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		request, err := http.NewRequest(http.MethodPost, server.URL+"/protected", nil)
		require.NoError(t, err)
		request.Header.Set("Accept", "text/html")

		response, err := client.Do(request)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, "/", cookieValue(t, response, "__Host-oidcauth_return"))
	})

	t.Run("a forged return cookie cannot redirect off this host", func(t *testing.T) {
		for _, target := range []string{"//evil.com", "https://evil.com/x", "not-a-path"} {
			idp := newFakeIDP(t)
			server, client := newTestServer(t, idp, "reader")
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			idp.LoginAs(map[string]any{"email": "mjn@cego.dk", "client_roles": []any{"reader"}})

			started := browserGet(t, client, server.URL+"/protected")
			_ = started.Body.Close()
			serverURL, err := url.Parse(server.URL)
			require.NoError(t, err)
			client.Jar.SetCookies(serverURL, []*http.Cookie{{Name: "__Host-oidcauth_return", Value: target, Path: "/"}})

			atProvider, err := client.Get(started.Header.Get("Location"))
			require.NoError(t, err)
			_ = atProvider.Body.Close()
			atCallback, err := client.Get(atProvider.Header.Get("Location"))
			require.NoError(t, err)
			_ = atCallback.Body.Close()

			assert.Equal(t, http.StatusFound, atCallback.StatusCode, target)
			assert.Equal(t, "/", atCallback.Header.Get("Location"), "login must not redirect to %s", target)
		}
	})

	t.Run("http issuer and base url are refused", func(t *testing.T) {
		idp := newFakeIDP(t)
		_, err := oidcauth.New(context.Background(), logger.NewMock(), oidcauth.Config{
			Issuer: "http://keycloak.example.com/realms/cego", ClientID: testClientID,
			ClientSecret: testClientSecret, BaseURL: "https://example.com",
		})
		require.ErrorContains(t, err, "issuer must be https")

		_, err = oidcauth.New(context.Background(), logger.NewMock(), oidcauth.Config{
			Issuer: idp.IssuerURL(), ClientID: testClientID,
			ClientSecret: testClientSecret, BaseURL: "http://example.com",
		}, oidcauth.WithHTTPClient(idp.Client()))
		require.ErrorContains(t, err, "base url must be https")
	})

	t.Run("a token authorized for another client is refused", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, _ := newTestServer(t, idp, "reader")
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		for _, claims := range []map[string]any{
			{"azp": "another-client", "client_roles": []any{"reader"}},
			{"aud": []string{testClientID, "another-client"}, "client_roles": []any{"reader"}},
			{"sub": "", "client_roles": []any{"reader"}},
		} {
			request, err := http.NewRequest(http.MethodGet, server.URL+"/protected", nil)
			require.NoError(t, err)
			request.Header.Set("Accept", "text/html")
			request.AddCookie(&http.Cookie{Name: "__Host-oidcauth_session", Value: idp.MintIDToken(t, claims)})

			response, err := client.Do(request)
			require.NoError(t, err)
			_ = response.Body.Close()
			assert.Equal(t, http.StatusFound, response.StatusCode, claims)
		}
	})

	t.Run("visiting the login route does not loop back to itself", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, client := newTestServer(t, idp, "reader")
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		response := browserGet(t, client, server.URL+oidcauth.LoginPath)
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, "/", cookieValue(t, response, "__Host-oidcauth_return"))
	})

	t.Run("logout never puts the token in the url", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, _ := newTestServer(t, idp, "reader")
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		token := idp.MintIDToken(t, map[string]any{"client_roles": []any{"reader"}})
		request, err := http.NewRequest(http.MethodPost, server.URL+oidcauth.LogoutPath, nil)
		require.NoError(t, err)
		request.AddCookie(&http.Cookie{Name: "__Host-oidcauth_session", Value: token})

		response, err := client.Do(request)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		location := response.Header.Get("Location")
		assert.NotContains(t, location, token)
		parsed, err := url.Parse(location)
		require.NoError(t, err)
		assert.Empty(t, parsed.Query().Get("id_token_hint"))
		assert.Equal(t, testClientID, parsed.Query().Get("client_id"))
		assert.Equal(t, server.URL+"/", parsed.Query().Get("post_logout_redirect_uri"))
	})

	t.Run("the openid scope cannot be dropped", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, _ := newTestServer(t, idp, "reader", oidcauth.WithScopes("email"))
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		response := browserGet(t, client, server.URL+"/protected")
		defer func() { _ = response.Body.Close() }()

		location, err := url.Parse(response.Header.Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "openid email", location.Query().Get("scope"))
	})

	t.Run("an api client authenticates with a bearer token", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, _ := newTestServer(t, idp, "reader")

		request, err := http.NewRequest(http.MethodGet, server.URL+"/protected", nil)
		require.NoError(t, err)
		request.Header.Set("Authorization", "Bearer "+idp.MintAccessToken(t, testClientID, map[string]any{
			"email": "robot@cego.dk", "client_roles": []any{"reader"},
		}))

		response, err := server.Client().Do(request)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("an api client is answered 401 rather than redirected", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, _ := newTestServer(t, idp, "reader")
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		response, err := client.Get(server.URL + "/protected")
		require.NoError(t, err)
		_ = response.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, response.StatusCode)

		request, err := http.NewRequest(http.MethodGet, server.URL+"/protected", nil)
		require.NoError(t, err)
		request.Header.Set("Authorization", "Bearer not.a.jwt")
		request.Header.Set("Accept", "text/html")

		response, err = client.Do(request)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()
		assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
	})

	t.Run("a bearer audience can differ from the client id", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, _ := newTestServer(t, idp, "reader", oidcauth.WithBearerAudience("rule-engine-api"))

		request, err := http.NewRequest(http.MethodGet, server.URL+"/protected", nil)
		require.NoError(t, err)
		request.Header.Set("Authorization", "Bearer "+idp.MintAccessToken(t, "rule-engine-api", map[string]any{
			"client_roles": []any{"reader"},
		}))

		response, err := server.Client().Do(request)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("a route can require authentication without any role", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, client := newTestServer(t, idp, "")
		idp.LoginAs(map[string]any{"email": "anyone@cego.dk"})

		response := browserGet(t, client, server.URL+"/protected")
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("roles are read from resource_access when there is no flat claim", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, client := newTestServer(t, idp, "tool-admin")
		idp.LoginAs(map[string]any{"email": "mjn@cego.dk", "resource_access": map[string]any{
			testClientID: map[string]any{"roles": []any{"tool-admin"}},
		}})

		response := browserGet(t, client, server.URL+"/protected")
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("http on loopback is allowed for local development", func(t *testing.T) {
		idp := newFakeIDP(t)
		_, err := oidcauth.New(context.Background(), logger.NewMock(), oidcauth.Config{
			Issuer: idp.IssuerURL(), ClientID: testClientID,
			ClientSecret: testClientSecret, BaseURL: "http://localhost:8080",
		}, oidcauth.WithHTTPClient(idp.Client()))
		require.NoError(t, err)
	})

	t.Run("the gate also works as chi middleware", func(t *testing.T) {
		idp := newFakeIDP(t)

		mux := http.NewServeMux()
		server := httptest.NewTLSServer(mux)
		t.Cleanup(server.Close)
		idp.AllowRedirectURI(server.URL + oidcauth.CallbackPath)

		auth, err := oidcauth.New(context.Background(), logger.NewMock(), oidcauth.Config{
			Issuer: idp.IssuerURL(), ClientID: testClientID,
			ClientSecret: testClientSecret, BaseURL: server.URL,
		}, oidcauth.WithHTTPClient(idp.Client()))
		require.NoError(t, err)

		auth.Register(mux)
		gate := auth.Middleware("reader")
		mux.Handle("GET /wrapped", gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := oidcauth.UserFromContext(r.Context())
			_, _ = w.Write([]byte(user.Email))
			assert.True(t, user.EmailVerified)
		})))

		jar, err := cookiejar.New(nil)
		require.NoError(t, err)
		client := server.Client()
		client.Jar = jar
		idp.LoginAs(map[string]any{"email": "mjn@cego.dk", "email_verified": true, "client_roles": []any{"reader"}})

		response := browserGet(t, client, server.URL+"/wrapped")
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("an authorization header that is not a bearer token is refused", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, client := newTestServer(t, idp, "reader")
		idp.LoginAs(map[string]any{"email": "mjn@cego.dk", "client_roles": []any{"reader"}})

		loggedIn := browserGet(t, client, server.URL+"/protected")
		_ = loggedIn.Body.Close()
		require.Equal(t, http.StatusOK, loggedIn.StatusCode)

		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		for _, authorization := range []string{"Basic dXNlcjpwYXNz", "bearer lowercase", "Bearer not.a.jwt"} {
			request, err := http.NewRequest(http.MethodGet, server.URL+"/protected", nil)
			require.NoError(t, err)
			request.Header.Set("Accept", "text/html")
			request.Header.Set("Authorization", authorization)

			response, err := client.Do(request)
			require.NoError(t, err)
			_ = response.Body.Close()

			assert.Equal(t, http.StatusUnauthorized, response.StatusCode, authorization)
		}
	})

	t.Run("the configuration is validated", func(t *testing.T) {
		idp := newFakeIDP(t)
		for _, tc := range []struct {
			cfg  oidcauth.Config
			want string
		}{
			{oidcauth.Config{Issuer: "not-a-url", ClientID: "c", ClientSecret: "s", BaseURL: "https://example.com"}, "issuer must be an absolute url"},
			{oidcauth.Config{Issuer: idp.IssuerURL(), ClientID: "c", ClientSecret: "s", BaseURL: "/relative"}, "base url must be an absolute url"},
			{oidcauth.Config{Issuer: idp.IssuerURL(), ClientID: "", ClientSecret: "s", BaseURL: "https://example.com"}, "client id is required"},
			{oidcauth.Config{Issuer: idp.IssuerURL(), ClientID: "c", ClientSecret: "", BaseURL: "https://example.com"}, "client secret is required"},
		} {
			_, err := oidcauth.New(context.Background(), logger.NewMock(), tc.cfg, oidcauth.WithHTTPClient(idp.Client()))
			require.ErrorContains(t, err, tc.want)
		}
	})

	t.Run("the standard name claims are exposed", func(t *testing.T) {
		idp := newFakeIDP(t)
		server, client := newTestServer(t, idp, "reader")
		idp.LoginAs(map[string]any{
			"email": "mjn@cego.dk", "given_name": "Mads", "family_name": "Nielsen",
			"preferred_username": "mjn", "client_roles": []any{"reader"},
		})

		response := browserGet(t, client, server.URL+"/names")
		defer func() { _ = response.Body.Close() }()

		body := make([]byte, 128)
		n, _ := response.Body.Read(body)
		assert.Equal(t, "Mads Nielsen mjn", string(body[:n]))
	})

	t.Run("the user logs as an ecs shaped group", func(t *testing.T) {
		user := oidcauth.User{
			Subject: "cb18311d", PreferredUsername: "mjn", Email: "mjn@cego.dk",
			Name: "Mads Jon Nielsen", Roles: []string{"reader", "process-admin"},
		}

		var out strings.Builder
		slog.New(slog.NewJSONHandler(&out, nil)).Info("logged in", "user", user)

		logged := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(out.String()), &logged))
		fields, ok := logged["user"].(map[string]any)
		require.True(t, ok, out.String())

		assert.Equal(t, "mjn", fields["id"])
		assert.Equal(t, "oidc", fields["type"])
		assert.Equal(t, "mjn@cego.dk", fields["email"])
		assert.Equal(t, "Mads Jon Nielsen", fields["full_name"])
		assert.Equal(t, []any{"reader", "process-admin"}, fields["roles"])
	})

	t.Run("the log id falls back to the subject", func(t *testing.T) {
		var out strings.Builder
		slog.New(slog.NewJSONHandler(&out, nil)).Info("logged in", "user", oidcauth.User{Subject: "cb18311d"})

		logged := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(out.String()), &logged))
		assert.Equal(t, "cb18311d", logged["user"].(map[string]any)["id"])
	})

	t.Run("discovery failure is reported", func(t *testing.T) {
		_, err := oidcauth.New(context.Background(), logger.NewMock(), oidcauth.Config{
			Issuer:       "https://127.0.0.1:1/realms/nope",
			ClientID:     testClientID,
			ClientSecret: testClientSecret,
			BaseURL:      "https://example.com",
		})
		assert.ErrorContains(t, err, "discovering issuer")
	})
}

func cookieValue(t *testing.T, response *http.Response, name string) string {
	t.Helper()
	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	t.Fatalf("response did not set cookie %s", name)
	return ""
}

func TestUserHasRole(t *testing.T) {
	user := oidcauth.User{Roles: []string{"reader", "process-admin"}}
	assert.True(t, user.HasRole("process-admin"))
	assert.False(t, user.HasRole("nope"))
	assert.False(t, oidcauth.User{}.HasRole("reader"))
}
