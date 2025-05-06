package cego

import (
	cego "github.com/cego/go-lib/logging"
	"io"
	"net/http"
	"time"
)

type ForwardAuthHandler struct {
	handler            http.Handler
	logger             cego.Logger
	forwardAuthUrl     string
	forwardAuthHost    string
	forwardAuthTimeout time.Duration
	httpClient         *http.Client
	renderer           *Renderer
}

func NewForwardAuthHandler(handler http.Handler, logger cego.Logger, forwardAuthUrl string, forwardAuthHost string, forwardAuthTimeout time.Duration) *ForwardAuthHandler {
	httpClient := &http.Client{}
	renderer := NewRenderer(logger)

	return &ForwardAuthHandler{
		handler:            handler,
		logger:             logger,
		forwardAuthUrl:     forwardAuthUrl,
		forwardAuthHost:    forwardAuthHost,
		forwardAuthTimeout: forwardAuthTimeout,
		httpClient:         httpClient,
		renderer:           renderer,
	}
}

func (rh *ForwardAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequest("GET", rh.forwardAuthUrl, nil)
	if err != nil {
		rh.renderer.Text(w, http.StatusInternalServerError, err.Error())
		rh.logger.Error(err.Error())
		return
	}

	proto := "https"
	if req.Header.Get("X-Forwarded-Proto") != "" {
		proto = req.Header.Get("X-Forwarded-Proto")
	}

	req.Header.Set("X-Forwarded-Method", r.Method)
	req.Header.Set("X-Forwarded-Proto", proto)
	req.Header.Set("X-Forwarded-Host", rh.forwardAuthHost)
	req.Header.Set("X-Forwarded-Uri", r.Header.Get("X-Forwarded-Uri"))
	req.Header.Set("User-Agent", r.Header.Get("User-Agent"))
	req.Header.Set("Cookie", r.Header.Get("Cookie"))
	req.Header.Set("Authorization", r.Header.Get("Authorization"))

	resp, err := rh.httpClient.Do(req)
	if err != nil {
		rh.renderer.Text(w, http.StatusInternalServerError, err.Error())
		rh.logger.Error(err.Error())
		return
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			rh.renderer.Text(w, http.StatusInternalServerError, err.Error())
			rh.logger.Error(err.Error())
		}
		rh.renderer.Data(w, resp.StatusCode, bodyBytes, resp.Header.Get("Content-Type"))
		return
	}

	rh.handler.ServeHTTP(w, r)
}
