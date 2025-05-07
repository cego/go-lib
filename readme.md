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

## Using ForwardAuthHandler

```go
mux := http.NewServeMux()
forwardAuth := cego.NewForwardAuth(logger, "https://sso.cego.dk/auth", "netbox.cego.dk")

mux.Handle("/data", forwardAuth.Handler(reverseProxy))
mux.Handle("/data", forwardAuth.HandlerFunc(func (w http.ResponseWrite, req *http.Request) {
	_,_ = w.Write()
}))
```

## Using Logger
```go
logger := cego.NewLogger()

logger.Debug("Very nice")

err := error.Error("A error")
logger.Error(err.Error)

handleFunc := func(writer http.ResponseWriter, request *http.Request) {
    logger.Debug("Very nice", cego.GetSlogAttrFromRequest(request))
}

// Setting your logger as the global one
logger := log.NewLogger()
slog.SetDefault(logger)
slog.Debug("Also in ecs format")
```

## Using Renderer
```go
logger := cego.NewLogger()
renderer := cego.NewRenderer(logger)
handleFunc := func(writer http.ResponseWriter, request *http.Request) {
    renderer.Text(w, http.StatusOK, "Action package excitement !!!")
}
```
