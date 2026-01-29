package cego

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cego/go-lib/headers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type FaultyResponseWriter struct {
	header http.Header
}

func (f *FaultyResponseWriter) Header() http.Header {
	if f.header == nil {
		f.header = make(http.Header)
	}
	return f.header
}

func (f *FaultyResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("forced write error")
}

func (f *FaultyResponseWriter) WriteHeader(int) {}

func TestRenderer(t *testing.T) {
	t.Run("JSON renders correctly", func(t *testing.T) {
		logger := &MockLogger{}
		renderer := NewRenderer(logger)
		rec := httptest.NewRecorder()

		data := map[string]string{"foo": "bar"}
		renderer.JSON(rec, http.StatusCreated, data)

		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get(headers.ContentType))
		assert.JSONEq(t, `{"foo":"bar"}`, rec.Body.String())
	})

	t.Run("JSON logs error on encoding failure", func(t *testing.T) {
		logger := &MockLogger{}
		renderer := NewRenderer(logger)
		rec := httptest.NewRecorder()

		// Channel cannot be marshaled to JSON
		badData := make(chan int)

		logger.On("Error", mock.MatchedBy(func(msg string) bool {
			return msg != ""
		}), mock.Anything).Return()

		renderer.JSON(rec, http.StatusOK, badData)

		logger.AssertExpectations(t)
	})

	t.Run("JSON logs error on write failure", func(t *testing.T) {
		logger := &MockLogger{}
		renderer := NewRenderer(logger)
		rec := &FaultyResponseWriter{}

		logger.On("Error", "forced write error", mock.Anything).Return()

		renderer.JSON(rec, http.StatusOK, map[string]string{"a": "b"})

		logger.AssertExpectations(t)
	})

	t.Run("Text renders correctly", func(t *testing.T) {
		logger := &MockLogger{}
		renderer := NewRenderer(logger)
		rec := httptest.NewRecorder()

		renderer.Text(rec, http.StatusTeapot, "I am a teapot")

		assert.Equal(t, http.StatusTeapot, rec.Code)
		assert.Equal(t, "text/plain; charset=utf-8", rec.Header().Get(headers.ContentType))
		assert.Equal(t, "I am a teapot", rec.Body.String())
	})

	t.Run("Text logs error on write failure", func(t *testing.T) {
		logger := &MockLogger{}
		renderer := NewRenderer(logger)
		rec := &FaultyResponseWriter{}

		logger.On("Error", "forced write error", mock.Anything).Return()

		renderer.Text(rec, http.StatusOK, "hello")

		logger.AssertExpectations(t)
	})

	t.Run("Data renders correctly", func(t *testing.T) {
		logger := &MockLogger{}
		renderer := NewRenderer(logger)
		rec := httptest.NewRecorder()

		renderer.Data(rec, http.StatusOK, []byte{0x01, 0x02}, "application/octet-stream")

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/octet-stream", rec.Header().Get(headers.ContentType))
		assert.Equal(t, []byte{0x01, 0x02}, rec.Body.Bytes())
	})

	t.Run("Data logs error on write failure", func(t *testing.T) {
		logger := &MockLogger{}
		renderer := NewRenderer(logger)
		rec := &FaultyResponseWriter{}

		logger.On("Error", "forced write error", mock.Anything).Return()

		renderer.Data(rec, http.StatusOK, []byte("test"), "text/plain")

		logger.AssertExpectations(t)
	})
}
