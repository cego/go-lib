package cego

import (
	"fmt"
	"github.com/stretchr/testify/mock"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLogger(t *testing.T) {
	t.Run("it can get request attr", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		logger := NewMockLogger()
		logger.Debug("Epic request data is attached", GetSlogAttrFromRequest(req))

		fmt.Println(GetSlogAttrFromRequest(req))

		// TODO: Figure out how mock.MatchedBy is working instead of using mock.Anything
		logger.AssertCalled(t, "Debug", "Epic request data is attached", mock.Anything)
	})

}
