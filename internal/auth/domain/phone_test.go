package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/domain"
)

func TestNewPhone(t *testing.T) {
	t.Run("should be valid", func(t *testing.T) {
		_, err := domain.NewPhone("+5511999999999")

		assert.NoError(t, err)
	})

	t.Run("should throw error when email is invalid", func(t *testing.T) {
		_, err := domain.NewPhone("999999999")

		assert.ErrorIs(t, err, domain.ErrPhoneInvalid)
	})

	t.Run("should throw error when email is empty", func(t *testing.T) {
		_, err := domain.NewPhone("")

		assert.ErrorIs(t, err, domain.ErrPhoneEmpty)
	})
}
