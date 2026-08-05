[![actions](https://img.shields.io/github/actions/workflow/status/cego/go-lib/actions.yml?branch=main)](https://github.com/cego/go-lib/actions)
[![license](https://img.shields.io/github/license/cego/go-lib)](https://npmjs.org/package/gitlab-ci-local)
[![Renovate](https://img.shields.io/badge/renovate-enabled-brightgreen.svg)](https://renovatebot.com)

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=cego_go-lib&metric=alert_status)](https://sonarcloud.io/dashboard?id=cego_go-lib)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=cego_go-lib&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=cego_go-lib)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=cego_go-lib&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=cego_go-lib)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=cego_go-lib&metric=security_rating)](https://sonarcloud.io/dashboard?id=cego_go-lib)

[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=cego_go-lib&metric=coverage)](https://sonarcloud.io/dashboard?id=cego_go-lib)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=cego_go-lib&metric=code_smells)](https://sonarcloud.io/dashboard?id=cego_go-lib)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=cego_go-lib&metric=duplicated_lines_density)](https://sonarcloud.io/dashboard?id=cego_go-lib)

## Installation
```go
import (
    "github.com/cego/go-lib/v2/logger"
    "github.com/cego/go-lib/v2/renderer"
    "github.com/cego/go-lib/v2/forwardauth"
    "github.com/cego/go-lib/v2/oidcauth"
    "github.com/cego/go-lib/v2/headers"
    "github.com/cego/go-lib/v2/serve"
    "github.com/cego/go-lib/v2/periodic"
)
```

## Using Logger
```go
l := logger.New()

l.Debug("Very nice")

err := errors.New("An error")
l.Error("An error occurred in readme", logger.GetSlogAttrFromError(err))

handleFunc := func(writer http.ResponseWriter, request *http.Request) {
    l.Debug("Very nice", logger.GetSlogAttrFromRequest(request))
}

// With custom log level
l := logger.NewWithLevel(slog.LevelInfo)

// Set as global slog default
slog.SetDefault(l)

// Testing with mock logger
l := logger.NewMock()
r := renderer.New(l)
```

## Using Renderer with builtin logging
```go
l := logger.New()
r := renderer.New(l)
handleFunc := func(writer http.ResponseWriter, request *http.Request) {
    r.Text(w, http.StatusOK, "Action package excitement !!!")
}
```

## Using ForwardAuthHandler

### Use builtin http client (timeout 10s)

```go
mux := http.NewServeMux()
fa := forwardauth.New(l, "https://sso.example.com/auth", "myservice.example.com")

mux.Handle("/data", fa.Handler(reverseProxy))
mux.Handle("/data", fa.HandlerFunc(func (w http.ResponseWriter, req *http.Request) {
	_,_ = w.Write()
}))
```

### Bring your own http client
```go
mux := http.NewServeMux()
httpClient := &http.Client{Timeout: time.Duration(1) * time.Second}
fa := forwardauth.New(l, "https://sso.example.com/auth", "myservice.example.com", forwardauth.WithHTTPClient(httpClient))

mux.Handle("/data", fa.Handler(reverseProxy))
mux.Handle("/data", fa.HandlerFunc(func (w http.ResponseWriter, req *http.Request) {
	_,_ = w.Write()
}))
```

## Using OidcAuth

Authorization code flow with PKCE for browsers, bearer tokens for api clients. The verified id token
is the session cookie, so there is no session store.

```go
mux := http.NewServeMux()
auth, err := oidcauth.New(context.Background(), l, oidcauth.Config{
	Issuer:       "https://keycloak.example.com/realms/cego",
	ClientID:     "myservice",
	ClientSecret: os.Getenv("MYSERVICE_OIDC_CLIENT_SECRET"),
	BaseURL:      "https://myservice.example.com",
})

auth.Register(mux) // Adds GET /auth/login, GET /auth/callback and POST /auth/logout

mux.Handle("GET /{$}", auth.HandlerFunc(index))                             // Authenticated
mux.Handle("GET /things", auth.HandlerFunc(things, "reader", "tool-admin")) // Either role
mux.Handle("POST /things/{id}/delete", auth.HandlerFunc(del, "tool-admin")) // That role

r.Use(auth.Middleware("reader")) // The same gate as chi middleware

// Inside a wrapped handler, or a template
user := oidcauth.UserFromContext(r.Context())
user.HasRole("tool-admin")
user.HasAnyRole("reader", "tool-admin")
```

- Register `<BaseURL>/auth/callback` on the client, or the provider rejects the login
- Roles are read from `client_roles` and `resource_access.<client>.roles`
- Issuer and base url must be https, except on loopback
- No session: browsers go to the provider, htmx gets `HX-Redirect`, api clients get `401`
- Logout is a `POST`, and hands the provider no token, so it asks the user to confirm
- Sessions cannot be revoked before the id token expires, so keep that lifetime short
- Cookies are `__Host-` prefixed, secure and `SameSite=Lax`, which is not a CSRF token
- `User` implements `slog.LogValuer`, so `"user", user` logs the ecs shaped group

### Options
```go
auth, err := oidcauth.New(ctx, l, cfg,
	oidcauth.WithHTTPClient(httpClient),          // default timeout 10s
	oidcauth.WithScopes("openid", "email"),       // default openid, profile, email
	oidcauth.WithRolesClaim("realm_roles"),       // default client_roles
	oidcauth.WithCookiePrefix("myservice"),       // default oidcauth
	oidcauth.WithBearerAudience("myservice-api"), // default the client id
)
```

## Headers
```go
req.Header.Get(headers.Authorization)
req.Header.Get(headers.XForwardedFor)
```

Available constants: `XForwardedProto`, `XForwardedMethod`, `XForwardedHost`, `XForwardedUri`, `XForwardedFor`, `Accept`, `UserAgent`, `Cookie`, `Authorization`, `RemoteUser`, `ContentType`

## Using Periodic

Context-aware periodic task execution with jitter support.

```go
ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer stop()

periodic.Run(ctx, 2*time.Second, time.Duration(rand.Intn(1000))*time.Millisecond, func() {
    fmt.Println("runs every 2 seconds until ctx is cancelled")
})
```

## Using Serve (Graceful Shutdown)

Graceful HTTP server shutdown with a configurable delay for load balancer deregistration.

```go
srv := serve.WithDefaults(&http.Server{Addr: ":8080", Handler: myHandler})

ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer stop()

err := serve.ListenAndServe(ctx, srv, slog.Default())
```
