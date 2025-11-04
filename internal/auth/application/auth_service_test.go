package application_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/application"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/domain"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/infrastructure"
	"github.com/viniosilva/ipanemaboxapi/mocks"
	"github.com/viniosilva/ipanemaboxapi/pkg"
)

var ctxMock = mock.AnythingOfType("*context.cancelCtx")

func TestAuthServiceImpl_Register(t *testing.T) {
	t.Run("should register successfully", func(t *testing.T) {
		input := application.RegisterInput{
			Name:     "John Doe",
			Email:    "john.doe@example.com",
			Password: "1a2b3c4d",
			Phone:    pkg.Pointer("+5511999999999"),
		}

		userRepo := mocks.NewMockUserRepository(t)
		userRepo.On("UserExistsByEmail", ctxMock, mock.AnythingOfType("domain.Email")).
			Return(false, nil)
		userRepo.On("CreateUser", ctxMock, mock.AnythingOfType("*domain.User")).Return(nil)

		s := application.NewAuthService(userRepo, nil)
		got, gotErr := s.Register(t.Context(), input)

		require.NoError(t, gotErr)
		assert.NotEmpty(t, got.ID)
		assert.Equal(t, input.Name, got.Name)
		assert.Equal(t, input.Email, string(got.Email))
		assert.Equal(t, *input.Phone, string(*got.Phone))
		assert.NotEmpty(t, got.Password)
	})

	t.Run("should throw error when email is invalid", func(t *testing.T) {
		input := application.RegisterInput{
			Email: "invalid-email",
		}

		userRepoMock := mocks.NewMockUserRepository(t)

		s := application.NewAuthService(userRepoMock, nil)
		_, gotErr := s.Register(t.Context(), input)

		assert.ErrorIs(t, gotErr, domain.ErrEmailInvalid)
		userRepoMock.AssertNotCalled(t, "UserExistsByEmail")
		userRepoMock.AssertNotCalled(t, "Register")
	})

	t.Run("should throw error when password is invalid", func(t *testing.T) {
		input := application.RegisterInput{
			Email:    "john.doe@example.com",
			Password: "",
		}

		userRepoMock := mocks.NewMockUserRepository(t)

		s := application.NewAuthService(userRepoMock, nil)
		_, gotErr := s.Register(t.Context(), input)

		assert.ErrorIs(t, gotErr, domain.ErrPasswordEmpty)
		userRepoMock.AssertNotCalled(t, "UserExistsByEmail")
		userRepoMock.AssertNotCalled(t, "Register")
	})

	t.Run("should throw error when phone is invalid", func(t *testing.T) {
		input := application.RegisterInput{
			Email:    "john.doe@example.com",
			Password: "1a2b3c4d",
			Phone:    pkg.Pointer("invalid-phone"),
		}

		userRepoMock := mocks.NewMockUserRepository(t)

		s := application.NewAuthService(userRepoMock, nil)
		_, gotErr := s.Register(t.Context(), input)

		assert.ErrorIs(t, gotErr, domain.ErrPhoneInvalid)
		userRepoMock.AssertNotCalled(t, "UserExistsByEmail")
		userRepoMock.AssertNotCalled(t, "Register")
	})

	t.Run("should throw error when name is invalid", func(t *testing.T) {
		input := application.RegisterInput{
			Name:     "",
			Email:    "john.doe@example.com",
			Password: "1a2b3c4d",
			Phone:    pkg.Pointer("+5511999999999"),
		}

		userRepoMock := mocks.NewMockUserRepository(t)

		s := application.NewAuthService(userRepoMock, nil)
		_, gotErr := s.Register(t.Context(), input)

		assert.ErrorIs(t, gotErr, domain.ErrUserNameEmpty)
		userRepoMock.AssertNotCalled(t, "UserExistsByEmail")
		userRepoMock.AssertNotCalled(t, "Register")
	})

	t.Run("should throw error when user already exists", func(t *testing.T) {
		input := application.RegisterInput{
			Name:     "John Doe",
			Email:    "john.doe@example.com",
			Password: "1a2b3c4d",
		}

		userRepoMock := mocks.NewMockUserRepository(t)

		userRepoMock.On("UserExistsByEmail", ctxMock, mock.AnythingOfType("domain.Email")).
			Return(true, nil)

		s := application.NewAuthService(userRepoMock, nil)
		_, gotErr := s.Register(t.Context(), input)

		assert.ErrorIs(t, gotErr, application.ErrUserAlreadyExists)
		userRepoMock.AssertNotCalled(t, "Register")
	})

	t.Run("should throw error when UserExistsByEmail returns error", func(t *testing.T) {
		input := application.RegisterInput{
			Name:     "John Doe",
			Email:    "john.doe@example.com",
			Password: "1a2b3c4d",
		}

		userRepoMock := mocks.NewMockUserRepository(t)

		userRepoMock.On("UserExistsByEmail", ctxMock, mock.AnythingOfType("domain.Email")).
			Return(false, assert.AnError)

		s := application.NewAuthService(userRepoMock, nil)
		_, gotErr := s.Register(t.Context(), input)

		assert.ErrorIs(t, gotErr, assert.AnError)
		userRepoMock.AssertNotCalled(t, "Register")
	})

	t.Run("should throw error when CreateUser returns error", func(t *testing.T) {
		input := application.RegisterInput{
			Name:     "John Doe",
			Email:    "john.doe@example.com",
			Password: "1a2b3c4d",
		}

		userRepoMock := mocks.NewMockUserRepository(t)

		userRepoMock.On("UserExistsByEmail", mock.Anything, mock.AnythingOfType("domain.Email")).
			Return(false, nil)
		userRepoMock.On("CreateUser", mock.Anything, mock.AnythingOfType("*domain.User")).Return(assert.AnError)

		s := application.NewAuthService(userRepoMock, nil)
		_, gotErr := s.Register(t.Context(), input)

		assert.ErrorIs(t, gotErr, assert.AnError)
	})
}

func TestAuthServiceImpl_Login(t *testing.T) {
	secretKey := "test_secret_key"
	serviceName := "ipanema-box-api"
	expiresAt := 1 * time.Minute

	password, err := domain.NewPassword("1a2b3c4d")
	require.NoError(t, err)

	email, err := domain.NewEmail("john.doe@example.com")
	require.NoError(t, err)

	t.Run("should login successfully", func(t *testing.T) {
		input := application.LoginInput{
			Email:    "john.doe@example.com",
			Password: "1a2b3c4d",
		}

		userRepoMock, err := domain.NewUser("John Doe", email, password, nil)
		require.NoError(t, err)

		userRepo := mocks.NewMockUserRepository(t)
		userRepo.On("GetUserByEmail", mock.Anything, mock.AnythingOfType("domain.Email")).Return(userRepoMock, nil)

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("SetTokenJWT",
			mock.Anything,
			mock.AnythingOfType("infrastructure.TokenJWTClaims"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("time.Duration"),
		).Return(nil)

		tokenSvc := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, expiresAt)
		s := application.NewAuthService(userRepo, tokenSvc)
		got, gotErr := s.Login(t.Context(), input)

		require.NoError(t, gotErr)
		assert.NotEmpty(t, got.Token)
	})

	t.Run("should throw error when password is empty", func(t *testing.T) {
		input := application.LoginInput{
			Email:    "john.doe@example.com",
			Password: "",
		}

		userRepoMock := mocks.NewMockUserRepository(t)

		tokenSvc := infrastructure.NewTokenService(nil, serviceName, secretKey, expiresAt)
		s := application.NewAuthService(userRepoMock, tokenSvc)
		_, gotErr := s.Login(t.Context(), input)

		assert.ErrorIs(t, gotErr, domain.ErrPasswordEmpty)
		userRepoMock.AssertNotCalled(t, "GetUserByEmail")
	})

	t.Run("should throw error when email is invalid", func(t *testing.T) {
		input := application.LoginInput{
			Email:    "invalid-email",
			Password: "1a2b3c4d",
		}

		userRepoMock := mocks.NewMockUserRepository(t)

		tokenSvc := infrastructure.NewTokenService(nil, serviceName, secretKey, expiresAt)
		s := application.NewAuthService(userRepoMock, tokenSvc)
		_, gotErr := s.Login(t.Context(), input)

		assert.ErrorIs(t, gotErr, domain.ErrEmailInvalid)
		userRepoMock.AssertNotCalled(t, "GetUserByEmail")
	})

	t.Run("should throw error user not exists", func(t *testing.T) {
		input := application.LoginInput{
			Email:    "john.doe@example.com",
			Password: "1a2b3c4d",
		}

		userRepoMock := mocks.NewMockUserRepository(t)
		userRepoMock.On("GetUserByEmail", mock.Anything, mock.AnythingOfType("domain.Email")).Return(nil, infrastructure.ErrRegisterNotFound)

		tokenSvc := infrastructure.NewTokenService(nil, serviceName, secretKey, expiresAt)
		s := application.NewAuthService(userRepoMock, tokenSvc)
		_, gotErr := s.Login(t.Context(), input)

		assert.ErrorIs(t, gotErr, application.ErrUserNotFound)
	})

	t.Run("should throw error when GetUserByEmail returns error", func(t *testing.T) {
		input := application.LoginInput{
			Email:    "john.doe@example.com",
			Password: "1a2b3c4d",
		}

		userRepoMock := mocks.NewMockUserRepository(t)
		userRepoMock.On("GetUserByEmail", mock.Anything, mock.AnythingOfType("domain.Email")).Return(nil, assert.AnError)

		tokenSvc := infrastructure.NewTokenService(nil, serviceName, secretKey, expiresAt)
		s := application.NewAuthService(userRepoMock, tokenSvc)
		_, gotErr := s.Login(t.Context(), input)

		assert.ErrorIs(t, gotErr, assert.AnError)
	})

	t.Run("should throw error when password is different", func(t *testing.T) {
		input := application.LoginInput{
			Email:    "john.doe@example.com",
			Password: "4d3c2b1a",
		}

		userRepoMock, err := domain.NewUser("John Doe", email, password, nil)
		require.NoError(t, err)

		userRepo := mocks.NewMockUserRepository(t)
		userRepo.On("GetUserByEmail", mock.Anything, mock.AnythingOfType("domain.Email")).Return(userRepoMock, nil)

		tokenSvc := infrastructure.NewTokenService(nil, serviceName, secretKey, expiresAt)
		s := application.NewAuthService(userRepo, tokenSvc)
		_, gotErr := s.Login(t.Context(), input)

		assert.ErrorIs(t, gotErr, application.ErrUserNotFound)
	})
}

func TestAuthServiceImpl_Logout(t *testing.T) {
	serviceName := "ipanema-box-api"
	secretKey := "test_secret_key"
	expiresAt := 1 * time.Minute

	t.Run("should logout successfully", func(t *testing.T) {
		userID := uuid.New()

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("DeleteTokenJWT", mock.Anything, userID).Return(nil)
		tokenSvc := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, expiresAt)

		s := application.NewAuthService(nil, tokenSvc)
		gotErr := s.Logout(context.Background(), userID)
		require.NoError(t, gotErr)
	})

	t.Run("should throw error when DeleteTokenJWT returns error", func(t *testing.T) {
		userID := uuid.New()

		tokenRepoMock := mocks.NewMockTokenRepository(t)
		tokenRepoMock.On("DeleteTokenJWT", mock.Anything, userID).Return(assert.AnError)
		tokenSvc := infrastructure.NewTokenService(tokenRepoMock, serviceName, secretKey, expiresAt)

		s := application.NewAuthService(nil, tokenSvc)
		gotErr := s.Logout(context.Background(), userID)
		assert.ErrorIs(t, gotErr, assert.AnError)
	})
}

func TestAuthServiceImpl_UpdateUserPassword(t *testing.T) {
	oldPasswordString := "abcd1234"
	oldPassword, err := domain.NewPassword(oldPasswordString)
	require.NoError(t, err)

	userMock, err := domain.NewUser("John Doe", "john.doe@example.com", oldPassword, nil)
	require.NoError(t, err)

	t.Run("should update user password successfully", func(t *testing.T) {
		uMock := pkg.Pointer(*userMock)
		input := application.UpdateUserPasswordInput{
			UserID:      uMock.ID,
			OldPassword: oldPasswordString,
			NewPassword: "1234abcd",
		}

		userRepo := mocks.NewMockUserRepository(t)
		userRepo.On("GetUserByID", mock.Anything, uMock.ID).Return(uMock, nil)
		userRepo.On("UpdateUser", mock.Anything, mock.AnythingOfType("*domain.User")).Return(nil)

		s := application.NewAuthService(userRepo, nil)

		gotErr := s.UpdateUserPassword(t.Context(), input)
		assert.NoError(t, gotErr)
	})

	t.Run("should throw error when old password is invalid", func(t *testing.T) {
		input := application.UpdateUserPasswordInput{
			UserID:      userMock.ID,
			OldPassword: "invalid-password",
			NewPassword: "1234abcd",
		}

		userRepo := mocks.NewMockUserRepository(t)
		userRepo.On("GetUserByID", mock.Anything, userMock.ID).Return(userMock, nil)

		s := application.NewAuthService(userRepo, nil)
		gotErr := s.UpdateUserPassword(t.Context(), input)

		assert.ErrorIs(t, gotErr, domain.ErrInvalidPassword)
		userRepo.AssertNotCalled(t, "UpdateUser")
	})

	t.Run("should throw error when old password does not match the user password", func(t *testing.T) {
		input := application.UpdateUserPasswordInput{
			UserID:      userMock.ID,
			OldPassword: "invalid-password",
			NewPassword: "1234abcd",
		}

		userRepo := mocks.NewMockUserRepository(t)
		userRepo.On("GetUserByID", mock.Anything, userMock.ID).Return(userMock, nil)

		s := application.NewAuthService(userRepo, nil)

		gotErr := s.UpdateUserPassword(t.Context(), input)

		assert.ErrorIs(t, gotErr, domain.ErrInvalidPassword)
		userRepo.AssertNotCalled(t, "UpdateUser")
	})

	t.Run("should throw error when new password is invalid", func(t *testing.T) {
		input := application.UpdateUserPasswordInput{
			UserID:      userMock.ID,
			OldPassword: oldPasswordString,
			NewPassword: "1234",
		}

		userRepo := mocks.NewMockUserRepository(t)
		s := application.NewAuthService(userRepo, nil)

		gotErr := s.UpdateUserPassword(t.Context(), input)

		assert.ErrorIs(t, gotErr, domain.ErrPasswordWeak)
		userRepo.AssertNotCalled(t, "GetUserByID")
		userRepo.AssertNotCalled(t, "UpdateUser")
	})

	t.Run("should throw error when user not found", func(t *testing.T) {
		input := application.UpdateUserPasswordInput{
			UserID:      userMock.ID,
			OldPassword: oldPasswordString,
			NewPassword: "1234abcd",
		}

		userRepo := mocks.NewMockUserRepository(t)
		userRepo.On("GetUserByID", mock.Anything, userMock.ID).Return(nil, infrastructure.ErrRegisterNotFound)

		s := application.NewAuthService(userRepo, nil)
		gotErr := s.UpdateUserPassword(t.Context(), input)

		assert.ErrorIs(t, gotErr, application.ErrUserNotFound)
		userRepo.AssertNotCalled(t, "UpdateUser")
	})

	t.Run("should throw error when GetUserByID returns error", func(t *testing.T) {
		input := application.UpdateUserPasswordInput{
			UserID:      userMock.ID,
			OldPassword: oldPasswordString,
			NewPassword: "1234abcd",
		}

		userRepo := mocks.NewMockUserRepository(t)
		userRepo.On("GetUserByID", mock.Anything, userMock.ID).Return(nil, assert.AnError)

		s := application.NewAuthService(userRepo, nil)
		gotErr := s.UpdateUserPassword(t.Context(), input)

		assert.ErrorIs(t, gotErr, assert.AnError)
		userRepo.AssertNotCalled(t, "UpdateUser")
	})

	t.Run("should throw error when UpdateUser returns error", func(t *testing.T) {
		input := application.UpdateUserPasswordInput{
			UserID:      userMock.ID,
			OldPassword: oldPasswordString,
			NewPassword: "1234abcd",
		}

		userRepo := mocks.NewMockUserRepository(t)
		userRepo.On("GetUserByID", mock.Anything, userMock.ID).Return(userMock, nil)
		userRepo.On("UpdateUser", mock.Anything, mock.AnythingOfType("*domain.User")).Return(assert.AnError)

		s := application.NewAuthService(userRepo, nil)
		gotErr := s.UpdateUserPassword(t.Context(), input)

		assert.ErrorIs(t, gotErr, assert.AnError)
	})
}
