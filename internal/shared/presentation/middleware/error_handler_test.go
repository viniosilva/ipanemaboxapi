package middleware_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/viniosilva/ipanemaboxapi/internal/shared/presentation/middleware"
	"github.com/viniosilva/ipanemaboxapi/pkg"
)

func TestErrorHandler(t *testing.T) {
	t.Run("should throw unauthorized error when error is ErrAuthHeaderRequired", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware.ErrorHandler())
		testingHandler := func(c *gin.Context) {
			c.Error(middleware.ErrAuthHeaderRequired)
		}
		router.GET("/testing", testingHandler)

		w, res := pkg.MakeRequestWithResponse[middleware.ServerErrorResponse](t, router, http.MethodGet, "/testing", nil)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "authorization header is required", res.Message)
	})

	t.Run("should throw internal server error when domain error is a not mapped domain custom error", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware.ErrorHandler())
		testingHandler := func(c *gin.Context) {
			c.Error(pkg.NewDomainError("customError", "custom error"))
		}
		router.GET("/testing", testingHandler)

		w, res := pkg.MakeRequestWithResponse[middleware.ServerErrorResponse](t, router, http.MethodGet, "/testing", nil)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "an unexpected error occurred", res.Message)
	})

	t.Run("should throw unprocessable entity error when is validation error", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware.ErrorHandler())
		testingHandler := func(c *gin.Context) {
			c.Error(pkg.ValidationError{Message: "validation error"})
		}
		router.GET("/testing", testingHandler)

		w, res := pkg.MakeRequestWithResponse[pkg.ValidationError](t, router, http.MethodGet, "/testing", nil)
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
		assert.Equal(t, "validation error", res.Message)
	})

	t.Run("should throw internal server error when error is not mapped", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware.ErrorHandler())
		testingHandler := func(c *gin.Context) {
			c.Error(assert.AnError)
		}
		router.GET("/testing", testingHandler)

		w, res := pkg.MakeRequestWithResponse[middleware.ServerErrorResponse](t, router, http.MethodGet, "/testing", nil)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "an unexpected error occurred", res.Message)
	})
}
