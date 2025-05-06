# Using ForwardAuthHandler

```go
mux := http.NewServeMux()
mux.Handle("/data", cego.NewForwardAuthHandler(func(w http.ResponseWriter, r *http.Request) { 
  // Do your stuff
}))
```