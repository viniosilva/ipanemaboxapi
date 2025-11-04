package domain

import (
	"github.com/go-playground/validator/v10"
	"github.com/viniosilva/ipanemaboxapi/pkg"
)

var (
	ErrPhoneEmpty   = pkg.NewDomainError("phoneEmpty", "phone is required")
	ErrPhoneInvalid = pkg.NewDomainError("phoneInvalid", "phone is invalid")
)

type Phone string

func NewPhone(value string) (Phone, error) {
	phone := Phone(value)
	err := phone.Validate()

	return phone, err
}

func (p Phone) Validate() error {
	if p == "" {
		return ErrPhoneEmpty
	}

	if err := validator.New().Var(p, "e164"); err != nil {
		return ErrPhoneInvalid
	}

	return nil
}
