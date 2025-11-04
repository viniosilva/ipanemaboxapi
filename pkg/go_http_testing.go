package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type requestOptions struct {
	bearerToken string
}

type requestOption func(*requestOptions)

func WithBearerAuthorization(token string) requestOption {
	return func(opts *requestOptions) {
		opts.bearerToken = token
	}
}

func MakeRequest(t *testing.T, router *gin.Engine, method string, path string, body any, opts ...requestOption) *httptest.ResponseRecorder {
	options := &requestOptions{}
	for _, opt := range opts {
		opt(options)
	}

	jsonBody, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(method, path, bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	if options.bearerToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", options.bearerToken))
	}

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	return w
}

func MakeRequestWithResponse[T any](t *testing.T, router *gin.Engine, method string, path string, body any, opts ...requestOption) (*httptest.ResponseRecorder, T) {
	w := MakeRequest(t, router, method, path, body, opts...)

	var res T
	err := json.Unmarshal(w.Body.Bytes(), &res)
	require.NoError(t, err)

	return w, res
}
