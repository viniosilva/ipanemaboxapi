package exception

import (
	"strings"

	"github.com/go-playground/validator/v10"
)

const ValidationExceptionName = "validation"

type ValidationException struct {
	Name   string
	Errors []string
	err    string
}

func NewValidationException(err error) *ValidationException {
	errs := []string{}
	validationErrors, _ := err.(validator.ValidationErrors)
	for _, e := range validationErrors {
		errs = append(errs, e.Error())
	}

	return &ValidationException{
		Name:   ValidationExceptionName,
		err:    strings.ReplaceAll(err.Error(), "\n", ", "),
		Errors: errs,
	}
}

func (impl *ValidationException) Error() string {
	return impl.err
}
