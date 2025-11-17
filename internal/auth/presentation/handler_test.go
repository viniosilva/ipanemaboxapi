package presentation_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/application"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/domain"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/infrastructure"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/presentation"
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

func TestAuthHandler_Register(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("should register successfully", func(t *testing.T) {
		reqBody := presentation.RegisterRequest{
			Name:     "John Doe",
			Email:    "test@example.com",
			Password: "a1b2c3d4",
			Phone:    pkg.Pointer("+5511999999999"),
		}

		userRepoMock := mocks.NewMockUserRepository(t)
		userRepoMock.On("UserExistsByEmail", mock.AnythingOfType("context.backgroundCtx"), mock.AnythingOfType("domain.Email")).Return(false, nil)
		userRepoMock.On("CreateUser", mock.AnythingOfType("context.backgroundCtx"), mock.AnythingOfType("*domain.User")).Return(nil)

		router := setupRouter(userRepoMock, nil)
		w, res := pkg.MakeRequestWithResponse[presentation.RegisterResponse](t, router, http.MethodPost, "/api/auth/register", reqBody)

		assert.Equal(t, http.StatusCreated, w.Code)
		assert.Equal(t, reqBody.Name, res.Name)
		assert.Equal(t, reqBody.Email, res.Email)
		assert.Equal(t, reqBody.Phone, res.Phone)
	})

	t.Run("should throw unprocessable entity error when payload is empty", func(t *testing.T) {
		reqBody := presentation.RegisterRequest{}

		userRepoMock := mocks.NewMockUserRepository(t)

		router := setupRouter(userRepoMock, nil)
		w, res := pkg.MakeRequestWithResponse[pkg.ValidationError](t, router, http.MethodPost, "/api/auth/register", reqBody)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
		assert.Equal(t, "validation error", res.Message)
		assert.Equal(t, "email", res.Err.Field)
		assert.Equal(t, "emailEmpty", res.Err.Tag)
		assert.Equal(t, "email is required", res.Err.Message)
	})

	t.Run("should throw unprocessable entity error when password is invalid", func(t *testing.T) {
		reqBody := presentation.RegisterRequest{
			Name:     "John Doe",
			Email:    "test@example.com",
			Password: "12345678",
			Phone:    pkg.Pointer("+5511999999999"),
		}

		userRepoMock := mocks.NewMockUserRepository(t)

		router := setupRouter(userRepoMock, nil)
		w, res := pkg.MakeRequestWithResponse[pkg.ValidationError](t, router, http.MethodPost, "/api/auth/register", reqBody)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
		assert.Equal(t, "password", res.Err.Field)
		assert.Equal(t, "passwordWeak", res.Err.Tag)
		assert.Equal(t, "password must contain at least 6 characters long, one letter and one number", res.Err.Message)
	})

	t.Run("should throw internal server error when UserExistsByEmail returns error", func(t *testing.T) {
		reqBody := presentation.RegisterRequest{
			Name:     "John Doe",
			Email:    "test@example.com",
			Password: "a1b2c3d4",
			Phone:    pkg.Pointer("+5511999999999"),
		}

		userRepoMock := mocks.NewMockUserRepository(t)
		userRepoMock.On("UserExistsByEmail", mock.AnythingOfType("context.backgroundCtx"), mock.AnythingOfType("domain.Email")).Return(false, assert.AnError)

		router := setupRouter(userRepoMock, nil)
		w, res := pkg.MakeRequestWithResponse[middleware.ServerErrorResponse](t, router, http.MethodPost, "/api/auth/register", reqBody)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "an unexpected error occurred", res.Message)
	})
}

func TestAuthHandler_Login(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("should authenticate user successfully", func(t *testing.T) {
		reqBody := presentation.LoginRequest{
			Email:    "test@example.com",
			Password: "a1b2c3d4",
		}
		password, err := domain.NewPassword(reqBody.Password)
		require.NoError(t, err)

		userMock, err := domain.NewUser("John Doe", domain.Email(reqBody.Email), password, nil)
		require.NoError(t, err)

		userRepoMock := mocks.NewMockUserRepository(t)
		userRepoMock.On("GetUserByEmail", mock.AnythingOfType("context.backgroundCtx"), mock.AnythingOfType("domain.Email")).Return(userMock, nil)

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("SetTokenJWT", mock.AnythingOfType("context.backgroundCtx"),
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("time.Duration"),
		).Return(nil)
		tokenRepoMock.On("SetRefreshToken", mock.AnythingOfType("context.backgroundCtx"),
			mock.AnythingOfType("string"),
			userMock.ID,
			mock.AnythingOfType("time.Duration"),
		).Return(nil)

		router := setupRouter(userRepoMock, tokenRepoMock)
		w, res := pkg.MakeRequestWithResponse[presentation.LoginResponse](t, router, http.MethodPost, "/api/auth/login", reqBody)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, res.AccessToken)
	})

	t.Run("should throw unprocessable entity error when user not exists", func(t *testing.T) {
		reqBody := presentation.LoginRequest{
			Email:    "test@example.com",
			Password: "a1b2c3d4",
		}

		userRepoMock := mocks.NewMockUserRepository(t)
		userRepoMock.On("GetUserByEmail", mock.AnythingOfType("context.backgroundCtx"), mock.AnythingOfType("domain.Email")).Return(nil, infrastructure.ErrRegisterNotFound)

		router := setupRouter(userRepoMock, nil)
		w, res := pkg.MakeRequestWithResponse[pkg.ValidationError](t, router, http.MethodPost, "/api/auth/login", reqBody)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
		assert.Equal(t, "password", res.Err.Field)
		assert.Equal(t, "userNotFound", res.Err.Tag)
		assert.Equal(t, "user not found", res.Err.Message)
	})

	t.Run("should throw internal server error when GetUserByEmail returns error", func(t *testing.T) {
		reqBody := presentation.LoginRequest{
			Email:    "test@example.com",
			Password: "a1b2c3d4",
		}

		userRepoMock := mocks.NewMockUserRepository(t)
		userRepoMock.On("GetUserByEmail", mock.AnythingOfType("context.backgroundCtx"), mock.AnythingOfType("domain.Email")).Return(nil, assert.AnError)

		tokenRepoMock := mocks.NewMockTokenRepository(t)

		router := setupRouter(userRepoMock, tokenRepoMock)
		w, res := pkg.MakeRequestWithResponse[middleware.ServerErrorResponse](t, router, http.MethodPost, "/api/auth/login", reqBody)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "an unexpected error occurred", res.Message)
	})
}

func TestAuthHandler_Logout(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("should logout successfully", func(t *testing.T) {
		userID := uuid.New()

		userRepoMock := mocks.NewMockUserRepository(t)
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
		tokenRepoMock.On("DeleteTokenJWT",
			mock.AnythingOfType("context.backgroundCtx"),
			userID,
		).Return(nil)
		tokenRepoMock.On("DeleteUserRefreshTokens",
			mock.AnythingOfType("context.backgroundCtx"),
			userID,
		).Return(nil)
		tokenSvc := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, tokenJWTExpiresAt, refreshTokenExpiresAt)
		token, err := tokenSvc.GenerateTokenJWT(t.Context(), userID)
		require.NoError(t, err)

		router := setupRouter(userRepoMock, tokenRepoMock)
		w := pkg.MakeRequest(t, router, http.MethodDelete, "/api/auth/logout", nil, pkg.WithBearerAuthorization(token))

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("should throw error when DeleteTokenJWT returns error", func(t *testing.T) {
		userID := uuid.New()

		userRepoMock := mocks.NewMockUserRepository(t)
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
		tokenRepoMock.On("DeleteTokenJWT",
			mock.AnythingOfType("context.backgroundCtx"),
			userID,
		).Return(assert.AnError)

		tokenSvc := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, tokenJWTExpiresAt, refreshTokenExpiresAt)
		token, err := tokenSvc.GenerateTokenJWT(t.Context(), userID)
		require.NoError(t, err)

		router := setupRouter(userRepoMock, tokenRepoMock)
		w, res := pkg.MakeRequestWithResponse[middleware.ServerErrorResponse](t, router, http.MethodDelete, "/api/auth/logout", nil, pkg.WithBearerAuthorization(token))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "an unexpected error occurred", res.Message)
	})
}

func TestAuthHandler_UpdateUserPassword(t *testing.T) {
	gin.SetMode(gin.TestMode)

	passwordStr := "a1b2c3d4"
	password, err := domain.NewPassword(passwordStr)
	require.NoError(t, err)

	t.Run("should update user password successfully", func(t *testing.T) {
		reqBody := presentation.UpdateUserPasswordRequest{
			OldPassword: passwordStr,
			NewPassword: "1234abcd",
		}

		userMock, err := domain.NewUser("john doe", domain.Email("john.doe@example.com"), password, nil)
		require.NoError(t, err)

		userRepoMock := mocks.NewMockUserRepository(t)
		userRepoMock.On("GetUserByID", mock.AnythingOfType("context.backgroundCtx"), userMock.ID).Return(userMock, nil)
		userRepoMock.On("UpdateUser", mock.AnythingOfType("context.backgroundCtx"), mock.AnythingOfType("*domain.User")).Return(nil)

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("SetTokenJWT",
			mock.AnythingOfType("*context.cancelCtx"),
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("time.Duration"),
		).Return(nil)
		tokenRepoMock.On("HasTokenJWT", mock.AnythingOfType("context.backgroundCtx"),
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
		).Return(true, nil)

		tokenSvc := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, tokenJWTExpiresAt, refreshTokenExpiresAt)
		token, err := tokenSvc.GenerateTokenJWT(t.Context(), userMock.ID)
		require.NoError(t, err)

		router := setupRouter(userRepoMock, tokenRepoMock)
		w := pkg.MakeRequest(t, router, http.MethodPut, "/api/auth/update-password", reqBody, pkg.WithBearerAuthorization(token))

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("should throw unprocessable entity error when old password is invalid", func(t *testing.T) {
		reqBody := presentation.UpdateUserPasswordRequest{
			OldPassword: "invalid-password",
			NewPassword: "1234abcd",
		}

		userMock, err := domain.NewUser("john doe", domain.Email("john.doe@example.com"), password, nil)
		require.NoError(t, err)

		userRepoMock := mocks.NewMockUserRepository(t)
		userRepoMock.On("GetUserByID", mock.AnythingOfType("context.backgroundCtx"), userMock.ID).Return(userMock, nil)

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("SetTokenJWT", mock.Anything,
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("time.Duration"),
		).Return(nil)
		tokenRepoMock.On("HasTokenJWT", mock.AnythingOfType("context.backgroundCtx"),
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
		).Return(true, nil)

		tokenSvc := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, tokenJWTExpiresAt, refreshTokenExpiresAt)
		token, err := tokenSvc.GenerateTokenJWT(t.Context(), userMock.ID)
		require.NoError(t, err)

		router := setupRouter(userRepoMock, tokenRepoMock)
		w, res := pkg.MakeRequestWithResponse[pkg.ValidationError](t, router, http.MethodPut, "/api/auth/update-password", reqBody, pkg.WithBearerAuthorization(token))

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
		assert.Equal(t, "old_password", res.Err.Field)
		assert.Equal(t, "invalidPassword", res.Err.Tag)
		assert.Equal(t, "invalid password", res.Err.Message)
	})

	t.Run("should throw internal server error when UpdateUser returns error", func(t *testing.T) {
		reqBody := presentation.UpdateUserPasswordRequest{
			OldPassword: passwordStr,
			NewPassword: "1234abcd",
		}

		userMock, err := domain.NewUser("john doe", domain.Email("john.doe@example.com"), password, nil)
		require.NoError(t, err)

		userRepoMock := mocks.NewMockUserRepository(t)
		userRepoMock.On("GetUserByID", mock.AnythingOfType("context.backgroundCtx"), userMock.ID).Return(userMock, nil)
		userRepoMock.On("UpdateUser", mock.AnythingOfType("context.backgroundCtx"), mock.AnythingOfType("*domain.User")).Return(assert.AnError)

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("SetTokenJWT",
			mock.AnythingOfType("*context.cancelCtx"),
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("time.Duration"),
		).Return(nil)
		tokenRepoMock.On("HasTokenJWT", mock.AnythingOfType("context.backgroundCtx"),
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
		).Return(true, nil)

		tokenSvc := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, tokenJWTExpiresAt, refreshTokenExpiresAt)
		token, err := tokenSvc.GenerateTokenJWT(t.Context(), userMock.ID)
		require.NoError(t, err)

		router := setupRouter(userRepoMock, tokenRepoMock)
		w, res := pkg.MakeRequestWithResponse[middleware.ServerErrorResponse](t, router, http.MethodPut, "/api/auth/update-password", reqBody, pkg.WithBearerAuthorization(token))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "an unexpected error occurred", res.Message)
	})

	t.Run("should throw unauthorized error when update user password there is not authorization header", func(t *testing.T) {
		reqBody := presentation.UpdateUserPasswordRequest{
			OldPassword: passwordStr,
			NewPassword: "1234abcd",
		}

		userRepoMock := mocks.NewMockUserRepository(t)

		router := setupRouter(userRepoMock, nil)
		w := pkg.MakeRequest(t, router, http.MethodPut, "/api/auth/update-password", reqBody)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

	})
}

func setupRouter(userRepoMock *mocks.MockUserRepository, tokenRepoMock *mocks.MockTokenRepository) *gin.Engine {
	tokenSvc := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, tokenJWTExpiresAt, refreshTokenExpiresAt)
	authSvc := application.NewAuthService(userRepoMock, tokenSvc)
	handler := presentation.NewAuthHandler(authSvc)

	router := gin.New()
	router.Use(middleware.ErrorHandler())
	presentation.SetupRouter(router.Group("/api"), handler, tokenSvc)

	return router
}

func TestAuthHandler_RefreshToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("should logout successfully", func(t *testing.T) {
		userID := uuid.New()

		userRepoMock := mocks.NewMockUserRepository(t)
		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("SetTokenJWT",
			mock.Anything, // ctx
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("time.Duration"),
		).Return(nil).Twice()
		tokenRepoMock.On("GetUserIDByRefreshToken",
			mock.AnythingOfType("context.backgroundCtx"),
			mock.AnythingOfType("string"),
		).Return(userID, nil)
		tokenRepoMock.On("SetRefreshToken",
			mock.AnythingOfType("context.backgroundCtx"),
			mock.AnythingOfType("string"),
			userID,
			mock.AnythingOfType("time.Duration"),
		).Return(nil)

		tokenSvc := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, tokenJWTExpiresAt, refreshTokenExpiresAt)
		token, err := tokenSvc.GenerateTokenJWT(t.Context(), userID)
		require.NoError(t, err)

		router := setupRouter(userRepoMock, tokenRepoMock)
		w, res := pkg.MakeRequestWithResponse[presentation.RefreshTokenResponse](t, router, http.MethodPost, "/api/auth/refresh", nil, pkg.WithBearerAuthorization(token))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, res.AccessToken)
		assert.Len(t, res.RefreshToken, 64)
	})

	t.Run("should throw error when GetUserIDByRefreshToken returns error", func(t *testing.T) {
		userID := uuid.New()

		userRepoMock := mocks.NewMockUserRepository(t)
		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("SetTokenJWT",
			mock.AnythingOfType("*context.cancelCtx"),
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("time.Duration"),
		).Return(nil)
		tokenRepoMock.On("GetUserIDByRefreshToken",
			mock.AnythingOfType("context.backgroundCtx"),
			mock.AnythingOfType("string"),
		).Return(nil, assert.AnError)

		tokenSvc := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, tokenJWTExpiresAt, refreshTokenExpiresAt)
		token, err := tokenSvc.GenerateTokenJWT(t.Context(), userID)
		require.NoError(t, err)

		router := setupRouter(userRepoMock, tokenRepoMock)
		w, res := pkg.MakeRequestWithResponse[middleware.ServerErrorResponse](t, router, http.MethodPost, "/api/auth/refresh", nil, pkg.WithBearerAuthorization(token))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "invalid token", res.Message)
	})
}
