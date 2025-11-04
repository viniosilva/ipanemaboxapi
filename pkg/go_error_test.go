package pkg_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/viniosilva/ipanemaboxapi/pkg"
)

type TestStruct struct {
	Email string `json:"email" example:"john.doe@example.com"`
}

func TestGetValidationErrors(t *testing.T) {
	t.Run("should return validation error", func(t *testing.T) {
		err := pkg.NewDomainError("emailEmpty", "email is required")
		validations := pkg.MapValidationErrors{
			"email": {err},
		}

		got, ok := pkg.GetValidationErrors(err, validations)
		assert.True(t, ok)

		var validationError pkg.ValidationError
		if errors.As(got, &validationError) {
			assert.Equal(t, "validation error", validationError.Error())
			assert.Equal(t, "emailEmpty", validationError.Err.Tag)
			assert.Equal(t, "email is required", validationError.Err.Message)
		}
	})

	t.Run("should return not ok when error is not in validations", func(t *testing.T) {
		errInValidation := pkg.NewDomainError("emailEmpty", "email is required")
		errNotInValidation := pkg.NewDomainError("emailInvalid", "email is invalid")
		validations := pkg.MapValidationErrors{
			"email": {errInValidation},
		}

		got, ok := pkg.GetValidationErrors(errNotInValidation, validations)
		assert.False(t, ok)
		assert.Nil(t, got)
	})
}
