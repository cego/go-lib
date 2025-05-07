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
    logger.Debug("Very nice")
}
```

## Using Renderer
```go
logger := cego.NewLogger()
renderer := cego.NewRenderer(logger)
handleFunc := func(writer http.ResponseWriter, request *http.Request) {
    renderer.Text(w, http.StatusOK, "Action package excitement !!!")
}
```
