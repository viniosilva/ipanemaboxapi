package domain

import (
	"github.com/go-playground/validator/v10"
	"github.com/viniosilva/ipanemaboxapi/pkg"
)

var (
	ErrEmailEmpty   = pkg.NewDomainError("emailEmpty", "email is required")
	ErrEmailInvalid = pkg.NewDomainError("emailInvalid", "email is invalid")
)

type Email string

func NewEmail(value string) (Email, error) {
	email := Email(value)
	err := email.Validate()

	return email, err
}

func (e Email) Validate() error {
	if e == "" {
		return ErrEmailEmpty
	}

	if err := validator.New().Var(e, "email"); err != nil {
		return ErrEmailInvalid
	}

	return nil
}
