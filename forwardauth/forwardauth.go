package forwardauth

import (
	"encoding/base64"
	"io"
	"net/http"
	"time"

	"github.com/cego/go-lib/headers"
	"github.com/cego/go-lib/logger"
	"github.com/cego/go-lib/renderer"
)

type OptionFunc func(f *ForwardAuth)

func WithHTTPClient(httpClient *http.Client) OptionFunc {
	return func(f *ForwardAuth) {
		f.httpClient = httpClient
	}
}

type ForwardAuth struct {
	logger         logger.Logger
	url            string
	xForwardedHost string
	httpClient     *http.Client
	renderer       *renderer.Renderer
}

func New(l logger.Logger, url string, xForwardedHost string, opts ...OptionFunc) *ForwardAuth {
	f := &ForwardAuth{
		logger:         l,
		url:            url,
		xForwardedHost: xForwardedHost,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		renderer:       renderer.New(l),
	}

	for _, opt := range opts {
		opt(f)
	}

	return f
}

func (f *ForwardAuth) HandlerFunc(handlerFunc http.HandlerFunc) http.Handler {
	return f.Handler(handlerFunc)
}

func (f *ForwardAuth) Handler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequest("GET", f.url, nil)
		if err != nil {
			f.renderer.Text(w, http.StatusInternalServerError, err.Error())
			f.logger.Error(err.Error())
			return
		}

		proto := "https"
		if r.Header.Get(headers.XForwardedProto) != "" {
			proto = r.Header.Get(headers.XForwardedProto)
		}

		req.Header.Set(headers.XForwardedMethod, r.Method)
		req.Header.Set(headers.XForwardedProto, proto)
		req.Header.Set(headers.XForwardedHost, f.xForwardedHost)
		req.Header.Set(headers.XForwardedUri, r.URL.RequestURI())
		req.Header.Set(headers.UserAgent, r.Header.Get(headers.UserAgent))
		req.Header.Set(headers.Cookie, r.Header.Get(headers.Cookie))
		req.Header.Set(headers.Authorization, r.Header.Get(headers.Authorization))

		passwordInUrl, passwordInUrlOk := r.URL.User.Password()
		if req.Header.Get(headers.Authorization) == "" && passwordInUrlOk {
			usernameInUrl := r.URL.User.Username()
			usernamePasswordEncoded := base64.StdEncoding.EncodeToString([]byte(usernameInUrl + ":" + passwordInUrl))
			req.Header.Set(headers.Authorization, "Basic "+usernamePasswordEncoded)
		}

		resp, err := f.httpClient.Do(req)
		if err != nil {
			f.renderer.Text(w, http.StatusInternalServerError, err.Error())
			f.logger.Error(err.Error())
			return
		}

		if resp.StatusCode != http.StatusOK {
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				f.renderer.Text(w, http.StatusInternalServerError, err.Error())
				f.logger.Error(err.Error())
				return
			}
			f.renderer.Data(w, resp.StatusCode, bodyBytes, resp.Header.Get(headers.ContentType))
			return
		}

		r.Header.Set(headers.RemoteUser, resp.Header.Get(headers.RemoteUser))

		handler.ServeHTTP(w, r)
	})
}
