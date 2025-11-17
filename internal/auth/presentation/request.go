package presentation

import (
	"github.com/viniosilva/ipanemaboxapi/internal/auth/application"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/domain"
	"github.com/viniosilva/ipanemaboxapi/pkg"
)

type RegisterRequest struct {
	Name     string  `json:"name" example:"John Doe"`
	Email    string  `json:"email" example:"john.doe@example.com"`
	Password string  `json:"password" example:"abcd1234!"`
	Phone    *string `json:"phone" example:"+5511999999999"`
}

var RegisterRequestValidations = pkg.MapValidationErrors{
	"name":     {domain.ErrUserNameEmpty},
	"email":    {domain.ErrEmailEmpty, domain.ErrEmailInvalid, application.ErrUserAlreadyExists},
	"password": {domain.ErrPasswordEmpty, domain.ErrPasswordTooLong, domain.ErrPasswordWeak},
	"phone":    {domain.ErrPhoneEmpty, domain.ErrPhoneInvalid},
}

type LoginRequest struct {
	Email    string `json:"email" example:"john.doe@example.com"`
	Password string `json:"password" example:"abcd1234!"`
}

var LoginRequestValidations = pkg.MapValidationErrors{
	"email":    {domain.ErrEmailEmpty, domain.ErrEmailInvalid},
	"password": {domain.ErrPasswordEmpty, application.ErrUserNotFound},
}

type UpdateUserPasswordRequest struct {
	OldPassword string `json:"old_password" example:"abcd1234!"`
	NewPassword string `json:"new_password" example:"abcd1234!"`
}

var UpdateUserPasswordRequestValidations = pkg.MapValidationErrors{
	"old_password": {domain.ErrPasswordEmpty, domain.ErrInvalidPassword},
	"new_password": {domain.ErrPasswordEmpty, domain.ErrPasswordTooLong, domain.ErrPasswordWeak},
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" example:"123e4567e89b12d3a456426614174000"`
}
