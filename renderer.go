package cego

import (
	"encoding/json"
	"net/http"

	"github.com/cego/go-lib/headers"
)

type Renderer struct {
	logger Logger
}

func NewRenderer(logger Logger) *Renderer {
	return &Renderer{logger: logger}
}

func (r *Renderer) JSON(writer http.ResponseWriter, status int, data interface{}) {
	writer.Header().Set(headers.ContentType, "application/json; charset=utf-8")
	writer.WriteHeader(status)

	err := json.NewEncoder(writer).Encode(data)
	if err != nil {
		r.logger.Error(err.Error())
		return
	}
}

func (r *Renderer) Text(writer http.ResponseWriter, status int, text string) {
	writer.Header().Set(headers.ContentType, "text/plain; charset=utf-8")
	writer.WriteHeader(status)

	_, err := writer.Write([]byte(text))
	if err != nil {
		r.logger.Error(err.Error())
		return
	}
}

func (r *Renderer) Data(writer http.ResponseWriter, status int, bytes []byte, contentType string) {
	writer.Header().Set(headers.ContentType, contentType)
	writer.WriteHeader(status)

	_, err := writer.Write(bytes)
	if err != nil {
		r.logger.Error(err.Error())
		return
	}
}
