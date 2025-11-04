package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/domain"
)

func TestNewUser(t *testing.T) {
	name := "John Doe"
	email, _ := domain.NewEmail("john.doe@example.com")
	password, _ := domain.NewPassword("abcd1234!")
	phone, _ := domain.NewPhone("+5511999999999")

	t.Run("should be valid", func(t *testing.T) {
		_, err := domain.NewUser(name, email, password, &phone)

		assert.NoError(t, err)
	})

	t.Run("should throw error when name is empty", func(t *testing.T) {
		name := ""
		_, err := domain.NewUser(name, email, password, &phone)

		assert.ErrorIs(t, err, domain.ErrUserNameEmpty)
	})
}
