package domain

import (
	"regexp"

	"github.com/viniosilva/ipanemaboxapi/pkg"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrPasswordEmpty   = pkg.NewDomainError("passwordEmpty", "password is required")
	ErrPasswordTooLong = pkg.NewDomainError("passwordTooLong", "password must be less than 72 characters long")
	ErrPasswordWeak    = pkg.NewDomainError("passwordWeak", "password must contain at least 6 characters long, one letter and one number")
	ErrInvalidPassword = pkg.NewDomainError("invalidPassword", "invalid password")
)

const (
	bCryptCost        = 10
	minPasswordLength = 6
	maxPasswordLength = 72
)

type Password string

func NewPassword(value string) (Password, error) {
	if err := ValidatePassword(value); err != nil {
		return Password(""), err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(value), bCryptCost)
	if err != nil {
		return Password(""), err
	}

	return Password(string(hash)), err
}

func ParsePasswordFromHash(hash string) Password {
	return Password(hash)
}

func ValidatePassword(value string) error {
	if value == "" {
		return ErrPasswordEmpty
	}
	if len(value) > maxPasswordLength {
		return ErrPasswordTooLong
	}
	if len(value) < minPasswordLength || // at least 6 characters long
		!regexp.MustCompile(`[a-zA-Z]`).MatchString(value) || // at least one letter
		!regexp.MustCompile(`[0-9]`).MatchString(value) { // at least one number
		return ErrPasswordWeak
	}

	return nil
}

func (p Password) Matches(password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(p), []byte(password))
	if err != nil {
		return ErrInvalidPassword
	}

	return nil
}
