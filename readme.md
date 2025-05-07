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
```

## Using Renderer
```go
type SomeStruct struct {
    render *cego.Renderer
}

func (h SomeStruct) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h.renderer.Text(w, http.StatusOK, "We are is healthy")
}
```
