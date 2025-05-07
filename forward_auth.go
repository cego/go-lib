package cego

import (
	"io"
	"net/http"
	"time"
)

type OptionsForwardAuthFunc func(f *ForwardAuth)

func WithHTTPClient(httpClient *http.Client) OptionsForwardAuthFunc {
	return func(f *ForwardAuth) {
		f.httpClient = httpClient
	}
}

type ForwardAuth struct {
	logger                    Logger
	forwardAuthUrl            string
	forwardAuthXForwardedHost string
	httpClient                *http.Client
	renderer                  *Renderer
}

func NewForwardAuth(logger Logger, forwardAuthUrl string, forwardAuthXForwardedHost string, opts ...OptionsForwardAuthFunc) *ForwardAuth {
	f := &ForwardAuth{
		logger:                    logger,
		forwardAuthUrl:            forwardAuthUrl,
		forwardAuthXForwardedHost: forwardAuthXForwardedHost,
		httpClient:                &http.Client{Timeout: 10 * time.Second},
		renderer:                  NewRenderer(logger),
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
		req, err := http.NewRequest("GET", f.forwardAuthUrl, nil)
		if err != nil {
			f.renderer.Text(w, http.StatusInternalServerError, err.Error())
			f.logger.Error(err.Error())
			return
		}

		proto := "https"
		if req.Header.Get("X-Forwarded-Proto") != "" {
			proto = req.Header.Get("X-Forwarded-Proto")
		}

		req.Header.Set("X-Forwarded-Method", r.Method)
		req.Header.Set("X-Forwarded-Proto", proto)
		req.Header.Set("X-Forwarded-Host", f.forwardAuthXForwardedHost)
		req.Header.Set("X-Forwarded-Uri", r.Header.Get("X-Forwarded-Uri"))
		req.Header.Set("User-Agent", r.Header.Get("User-Agent"))
		req.Header.Set("Cookie", r.Header.Get("Cookie"))
		req.Header.Set("Authorization", r.Header.Get("Authorization"))

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
			}
			f.renderer.Data(w, resp.StatusCode, bodyBytes, resp.Header.Get("Content-Type"))
			return
		}

		r.Header.Set("Remote-User", resp.Header.Get("Remote-User"))

		handler.ServeHTTP(w, r)
	})
}
