package pkg

import (
	"errors"
	"fmt"
	"slices"
)

const validationErrorMessage = "validation error"

type DomainError struct {
	code   string
	errMsg string
}

func (e DomainError) Code() string {
	return e.code
}

func (e DomainError) Error() string {
	return e.errMsg
}

func NewDomainError(code string, errMsg string) DomainError {
	return DomainError{code: code, errMsg: errMsg}
}

type ValidationError struct {
	Message string                 `json:"message" example:"validation error"`
	Err     ValidationErrorDetails `json:"error"`
}

type ValidationErrorDetails struct {
	Field   string `json:"field" example:"email"`
	Tag     string `json:"tag" example:"emailEmpty"`
	Message string `json:"message" example:"email is required"`
}

func newValidationErrorDetail(field string, err error) ValidationErrorDetails {
	details := ValidationErrorDetails{
		Field:   field,
		Tag:     fmt.Sprintf("%T", err),
		Message: err.Error(),
	}

	var vErr DomainError
	if errors.As(err, &vErr) {
		details.Tag = vErr.Code()
	}

	return details
}

func (e ValidationError) Error() string {
	return e.Message
}

type MapValidationErrors map[string][]error

func GetValidationErrors(err error, validations map[string][]error) (error, bool) {
	for field, validationErrs := range validations {
		if slices.Contains(validationErrs, err) {
			return ValidationError{
				Message: validationErrorMessage,
				Err:     newValidationErrorDetail(field, err),
			}, true
		}
	}

	return nil, false
}
