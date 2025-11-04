package pkg

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const (
	pathRouterTesting = "/testing"
)

type payloadTesting struct {
	Message string `json:"message"`
}

func TestMakeRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	routerTesting := gin.New()
	routerTesting.GET(pathRouterTesting, func(c *gin.Context) {
		if h := c.GetHeader("Authorization"); h != "" && h != "Bearer testing" {
			c.Status(http.StatusUnauthorized)
			return
		}
		c.JSON(http.StatusOK, payloadTesting{Message: "GET testing ok"})
	})
	routerTesting.POST(pathRouterTesting, func(c *gin.Context) {
		c.JSON(http.StatusOK, payloadTesting{Message: "POST testing ok"})
	})

	t.Run("should be successfull when GET", func(t *testing.T) {
		got := MakeRequest(t, routerTesting, http.MethodGet, pathRouterTesting, nil)

		assert.Equal(t, http.StatusOK, got.Code)
	})

	t.Run("should be successfull when GET with response", func(t *testing.T) {
		got, res := MakeRequestWithResponse[payloadTesting](t, routerTesting, http.MethodGet, pathRouterTesting, nil)

		assert.Equal(t, http.StatusOK, got.Code)
		assert.Equal(t, "GET testing ok", res.Message)
	})

	t.Run("should be successfull when GET with response and bearer option", func(t *testing.T) {
		got, res := MakeRequestWithResponse[payloadTesting](t, routerTesting, http.MethodGet, pathRouterTesting, nil, WithBearerAuthorization("testing"))

		assert.Equal(t, http.StatusOK, got.Code)
		assert.Equal(t, "GET testing ok", res.Message)
	})

	t.Run("should throw unauthorized error GET with invalid bearer option", func(t *testing.T) {
		got := MakeRequest(t, routerTesting, http.MethodGet, pathRouterTesting, nil, WithBearerAuthorization("invalid"))

		assert.Equal(t, http.StatusUnauthorized, got.Code)
	})

	t.Run("should be successfull when POST", func(t *testing.T) {
		payload := payloadTesting{Message: "posting"}
		got := MakeRequest(t, routerTesting, http.MethodPost, pathRouterTesting, payload)

		assert.Equal(t, http.StatusOK, got.Code)
	})

	t.Run("should be successfull when POST with response", func(t *testing.T) {
		payload := payloadTesting{Message: "posting"}
		got, res := MakeRequestWithResponse[payloadTesting](t, routerTesting, http.MethodPost, pathRouterTesting, payload)

		assert.Equal(t, http.StatusOK, got.Code)
		assert.Equal(t, "POST testing ok", res.Message)
	})
}
