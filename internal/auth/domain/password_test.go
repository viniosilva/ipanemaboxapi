package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/domain"
)

func TestNewPassword(t *testing.T) {
	t.Run("should be valid", func(t *testing.T) {
		_, err := domain.NewPassword("1a2b3c4d")

		assert.NoError(t, err)
	})

	t.Run("should throw error when email is empty", func(t *testing.T) {
		_, err := domain.NewPassword("")

		assert.ErrorIs(t, err, domain.ErrPasswordEmpty)
	})

	t.Run("should throw error when password is too short", func(t *testing.T) {
		_, err := domain.NewPassword("1234567")

		assert.ErrorIs(t, err, domain.ErrPasswordWeak)
	})

	t.Run("should throw error when password is too long", func(t *testing.T) {
		_, err := domain.NewPassword("12345678901234567890123456789012345678901234567890123456789012345678901234567890")

		assert.ErrorIs(t, err, domain.ErrPasswordTooLong)
	})

	t.Run("should throw error when password does contain only numbers", func(t *testing.T) {
		_, err := domain.NewPassword("1234567890")

		assert.ErrorIs(t, err, domain.ErrPasswordWeak)
	})

	t.Run("should throw error when password does contain only letters", func(t *testing.T) {
		_, err := domain.NewPassword("abcdefghijklmnopqrstuvwxyz")

		assert.ErrorIs(t, err, domain.ErrPasswordWeak)
	})
}

func TestParsePasswordFromHash(t *testing.T) {
	t.Run("should parse password from hash", func(t *testing.T) {
		got := domain.ParsePasswordFromHash("$2a$10$ISXr4lBQr5b4lAeDDBpjn.dz8lkMIsf51G1gIL8Yoyc6IDF6pFAAi")

		assert.IsType(t, domain.Password(""), got)
	})
}

func TestPassword_Matches(t *testing.T) {
	password, err := domain.NewPassword("1a2b3c4d")
	require.NoError(t, err)

	t.Run("should return true when password matches", func(t *testing.T) {
		got := password.Matches("1a2b3c4d")
		assert.NoError(t, got)
	})

	t.Run("should return false when password does not match", func(t *testing.T) {
		got := password.Matches("a1b2c3d4")
		assert.ErrorIs(t, got, domain.ErrInvalidPassword)
	})
}
