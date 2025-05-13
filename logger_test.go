package cego

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
)

func TestLogger(t *testing.T) {
	t.Run("it can get request attr", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		logger := NewMockLogger()
		logger.Debug("Epic request data is attached", GetSlogAttrFromRequest(req))

		// TODO: Figure out how mock.MatchedBy is working instead of using mock.Anything
		logger.AssertCalled(t, "Debug", "Epic request data is attached", mock.Anything)
	})

	t.Run("it can get err attr", func(t *testing.T) {
		err := errors.New("test error")
		logger := NewMockLogger()
		logger.Error("Something has failed here", GetSlogAttrFromError(err))

		// TODO: Figure out how mock.MatchedBy is working instead of using mock.Anything
		logger.AssertCalled(t, "Error", "Something has failed here", mock.Anything)
	})

}
