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
    "github.com/cego/go-lib/logger"
    "github.com/cego/go-lib/renderer"
    "github.com/cego/go-lib/forwardauth"
    "github.com/cego/go-lib/headers"
)
```

## Using Logger
```go
logger := logger.New()

logger.Debug("Very nice")

err := error.Error("An error")
logger.Error("An error occurred in readme", logger.GetSlogAttrFromError(err))

handleFunc := func(writer http.ResponseWriter, request *http.Request) {
    logger.Debug("Very nice", logger.GetSlogAttrFromRequest(request))
}

// Setting your logger as the global one
l := logger.New()
slog.SetDefault(l)
slog.Debug("Also in ecs format")

// With custom log level
l := logger.New().WithLogLevel(slog.LevelInfo)
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
mux.Handle("/data", fa.HandlerFunc(func (w http.ResponseWrite, req *http.Request) {
	_,_ = w.Write()
}))
```

### Bring your own http client
```go
mux := http.NewServeMux()
httpClient := &http.Client{Timeout: time.Duration(1) * time.Second}
fa := forwardauth.New(l, "https://sso.example.com/auth", "myservice.example.com", forwardauth.WithHTTPClient(httpClient))

mux.Handle("/data", fa.Handler(reverseProxy))
mux.Handle("/data", fa.HandlerFunc(func (w http.ResponseWrite, req *http.Request) {
	_,_ = w.Write()
}))
```

## Testing with Mock Logger
```go
l := logger.NewMock()
r := renderer.New(l)
```

## Headers
```go
req.Header.Get(headers.Authorization)
req.Header.Get(headers.XForwardedFor)
```

Available constants: `XForwardedProto`, `XForwardedMethod`, `XForwardedHost`, `XForwardedUri`, `XForwardedFor`, `Accept`, `UserAgent`, `Cookie`, `Authorization`, `RemoteUser`, `ContentType`
