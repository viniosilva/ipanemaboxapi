package infrastructure_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/domain"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/infrastructure"
	"github.com/viniosilva/ipanemaboxapi/mocks"
)

func TestTokenService_GenerateToken(t *testing.T) {
	serviceName := "ipanema-box-api"
	secretKey := "test_secret_key"
	expiresAt := 1 * time.Minute

	t.Run("should generate token successfully", func(t *testing.T) {
		user, err := domain.NewUser("John Doe", "john.doe@example.com", "123", nil)
		require.NoError(t, err)

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("SetTokenJWT",
			mock.Anything,
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("time.Duration"),
		).Return(nil)

		s := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, expiresAt)
		got, gotErr := s.GenerateTokenJWT(t.Context(), *user)

		require.NoError(t, gotErr)
		assert.NotEmpty(t, got)
	})

	t.Run("should generate token successfully when secret key is empty", func(t *testing.T) {
		user, err := domain.NewUser("John Doe", "john.doe@example.com", "123", nil)
		require.NoError(t, err)

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("SetTokenJWT",
			mock.Anything,
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("time.Duration"),
		).Return(nil)

		secretKey := ""
		s := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, expiresAt)
		_, gotErr := s.GenerateTokenJWT(t.Context(), *user)

		require.NoError(t, gotErr)
		tokenRepoMock.AssertNotCalled(t, "SetTokenJWT")
	})
}

func TestTokenService_ValidateToken(t *testing.T) {
	serviceName := "ipanema-box-api"
	secretKey := "test_secret_key"
	expiresAt := 1 * time.Minute

	t.Run("should validate token successfully", func(t *testing.T) {
		user, err := domain.NewUser("John Doe", "john.doe@example.com", "123", nil)
		require.NoError(t, err)

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("SetTokenJWT",
			mock.Anything,
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("time.Duration"),
		).Return(nil)
		tokenRepoMock.On("HasTokenJWT",
			mock.Anything,
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
		).Return(true, nil)

		s := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, expiresAt)
		token, err := s.GenerateTokenJWT(t.Context(), *user)
		require.NoError(t, err)

		got, gotErr := s.ValidateTokenJWT(t.Context(), token)
		require.NoError(t, gotErr)

		assert.NotEmpty(t, got.ID)
		assert.Equal(t, user.ID.String(), got.Subject)
		assert.True(t, got.ExpiresAt.After(time.Now()))
	})

	t.Run("should throw error when token is expired", func(t *testing.T) {
		user, err := domain.NewUser("John Doe", "john.doe@example.com", "123", nil)
		require.NoError(t, err)

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("SetTokenJWT",
			mock.Anything,
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("time.Duration"),
		).Return(nil)

		expiresAt := -1 * time.Minute
		s := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, expiresAt)
		token, err := s.GenerateTokenJWT(t.Context(), *user)
		require.NoError(t, err)

		_, gotErr := s.ValidateTokenJWT(t.Context(), token)
		assert.ErrorIs(t, gotErr, infrastructure.ErrInvalidToken)
		tokenRepoMock.AssertNotCalled(t, "HasTokenJWT")
	})

	t.Run("should throw error when token has revoked", func(t *testing.T) {
		user, err := domain.NewUser("John Doe", "john.doe@example.com", "123", nil)
		require.NoError(t, err)

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("SetTokenJWT",
			mock.Anything,
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("time.Duration"),
		).Return(nil)
		tokenRepoMock.On("HasTokenJWT",
			mock.Anything,
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
		).Return(false, nil)

		s := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, expiresAt)
		token, err := s.GenerateTokenJWT(t.Context(), *user)
		require.NoError(t, err)

		_, gotErr := s.ValidateTokenJWT(t.Context(), token)
		assert.ErrorIs(t, gotErr, infrastructure.ErrInvalidToken)
	})

	t.Run("should throw error when HasTokenJWT returns error", func(t *testing.T) {
		user, err := domain.NewUser("John Doe", "john.doe@example.com", "123", nil)
		require.NoError(t, err)

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("SetTokenJWT",
			mock.Anything,
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("time.Duration"),
		).Return(nil)
		tokenRepoMock.On("HasTokenJWT",
			mock.Anything,
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
		).Return(false, assert.AnError)

		s := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, expiresAt)
		token, err := s.GenerateTokenJWT(t.Context(), *user)
		require.NoError(t, err)

		_, gotErr := s.ValidateTokenJWT(t.Context(), token)
		assert.ErrorIs(t, gotErr, assert.AnError)
	})
}

func TestTokenService_RevokeTokenJWT(t *testing.T) {
	serviceName := "ipanema-box-api"
	secretKey := "test_secret_key"
	expiresAt := 1 * time.Minute

	t.Run("should revoke token successfully", func(t *testing.T) {
		user, err := domain.NewUser("John Doe", "john.doe@example.com", "123", nil)
		require.NoError(t, err)

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("DeleteTokenJWT",
			mock.Anything,
			user.ID,
		).Return(nil)

		s := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, expiresAt)
		gotErr := s.RevokeTokenJWT(context.Background(), user.ID)
		require.NoError(t, gotErr)
	})

	t.Run("should revoke token successfully when token is not found", func(t *testing.T) {
		user, err := domain.NewUser("John Doe", "john.doe@example.com", "123", nil)
		require.NoError(t, err)

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("DeleteTokenJWT",
			mock.Anything,
			user.ID,
		).Return(infrastructure.ErrRegisterNotFound)

		s := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, expiresAt)
		gotErr := s.RevokeTokenJWT(context.Background(), user.ID)
		require.NoError(t, gotErr)
	})

	t.Run("should throw error when DeleteTokenJWT returns error", func(t *testing.T) {
		user, err := domain.NewUser("John Doe", "john.doe@example.com", "123", nil)
		require.NoError(t, err)

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("DeleteTokenJWT",
			mock.Anything,
			user.ID,
		).Return(assert.AnError)

		s := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, expiresAt)
		gotErr := s.RevokeTokenJWT(context.Background(), user.ID)
		assert.ErrorIs(t, gotErr, assert.AnError)
	})
}
