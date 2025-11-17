package middleware_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/infrastructure"
	"github.com/viniosilva/ipanemaboxapi/internal/shared/presentation/middleware"
	"github.com/viniosilva/ipanemaboxapi/mocks"
	"github.com/viniosilva/ipanemaboxapi/pkg"
)

const (
	serviceName           = "ipanema-box-api"
	secretKey             = "test_secret_key"
	tokenJWTExpiresAt     = 1 * time.Minute
	refreshTokenExpiresAt = 7 * 24 * time.Hour // 7 days
)

func TestAuthenticateMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("should authenticate user successfully", func(t *testing.T) {
		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("SetTokenJWT",
			mock.AnythingOfType("*context.cancelCtx"),
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("time.Duration"),
		).Return(nil)
		tokenRepoMock.On("HasTokenJWT",
			mock.AnythingOfType("context.backgroundCtx"),
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
		).Return(true, nil)

		tokenSvc := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, tokenJWTExpiresAt, refreshTokenExpiresAt)
		token, err := tokenSvc.GenerateTokenJWT(t.Context(), uuid.New())
		require.NoError(t, err)

		router := gin.New()
		router.Use(middleware.ErrorHandler())
		testingHandler := func(ctx *gin.Context) {
			ctx.Status(http.StatusOK)
		}
		router.GET("/testing", middleware.AuthenticateMiddleware(tokenSvc), testingHandler)

		w := pkg.MakeRequest(t, router, http.MethodGet, "/testing", nil, pkg.WithBearerAuthorization(token))

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should throw unauthorized error when token is empty", func(t *testing.T) {
		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenSvc := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, tokenJWTExpiresAt, refreshTokenExpiresAt)

		router := gin.New()
		router.Use(middleware.ErrorHandler())
		testingHandler := func(ctx *gin.Context) {
			ctx.Status(http.StatusOK)
		}
		router.GET("/testing", middleware.AuthenticateMiddleware(tokenSvc), testingHandler)

		w, res := pkg.MakeRequestWithResponse[pkg.ValidationError](t, router, http.MethodGet, "/testing", nil, pkg.WithBearerAuthorization(""))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "authorization header is required", res.Message)
	})

	t.Run("should throw unauthorized error header prefix invalid", func(t *testing.T) {
		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenSvc := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, tokenJWTExpiresAt, refreshTokenExpiresAt)

		router := gin.New()
		router.Use(middleware.ErrorHandler())
		testingHandler := func(ctx *gin.Context) {
			ctx.Status(http.StatusOK)
		}
		router.GET("/testing", middleware.AuthenticateMiddleware(tokenSvc), testingHandler)

		req := httptest.NewRequest(http.MethodGet, "/testing", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "invalid authorization header")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		var res pkg.ValidationError
		err := json.Unmarshal(w.Body.Bytes(), &res)
		require.NoError(t, err)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "authorization header must start with Bearer", res.Message)
	})

	t.Run("should throw unauthorized error when token is invalid", func(t *testing.T) {
		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenSvc := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, tokenJWTExpiresAt, refreshTokenExpiresAt)
		router := gin.New()
		router.Use(middleware.ErrorHandler())
		testingHandler := func(ctx *gin.Context) {
			ctx.Status(http.StatusOK)
		}
		router.GET("/testing", middleware.AuthenticateMiddleware(tokenSvc), testingHandler)

		w, res := pkg.MakeRequestWithResponse[pkg.ValidationError](t, router, http.MethodGet, "/testing", nil, pkg.WithBearerAuthorization("invalid.token.jwt"))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "invalid token", res.Message)
	})
}

func TestGetCtxUserID(t *testing.T) {
	t.Run("should return user ID successfully", func(t *testing.T) {
		userID := uuid.New()

		ctx := &gin.Context{}
		ctx.Set(middleware.UserIDKey, userID.String())

		got, err := middleware.GetCtxUserID(ctx)
		require.NoError(t, err)

		assert.Equal(t, userID, got)
	})

	t.Run("should return error when user ID is not found", func(t *testing.T) {
		_, err := middleware.GetCtxUserID(&gin.Context{})

		assert.ErrorIs(t, err, middleware.ErrTokenUserIDNotExists)
	})

	t.Run("should return error when user ID is not a valid UUID", func(t *testing.T) {
		ctx := &gin.Context{}
		ctx.Set(middleware.UserIDKey, "invalid")
		_, err := middleware.GetCtxUserID(ctx)

		assert.ErrorIs(t, err, middleware.ErrInvalidUserID)
	})
}
