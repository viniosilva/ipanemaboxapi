package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/domain"
)

func TestNewEmail(t *testing.T) {
	t.Run("should be valid", func(t *testing.T) {
		_, err := domain.NewEmail("test@example.com")

		assert.NoError(t, err)
	})

	t.Run("should throw error when email is invalid", func(t *testing.T) {
		_, err := domain.NewEmail("test@example")

		assert.ErrorIs(t, err, domain.ErrEmailInvalid)
	})

	t.Run("should throw error when email is empty", func(t *testing.T) {
		_, err := domain.NewEmail("")

		assert.ErrorIs(t, err, domain.ErrEmailEmpty)
	})
}
