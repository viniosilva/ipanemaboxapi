package application

import (
	"github.com/google/uuid"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/domain"
)

type RegisterOutput struct {
	ID       uuid.UUID
	Name     string
	Email    domain.Email
	Password domain.Password
	Phone    *domain.Phone
}

type LoginOutput struct {
	AccessToken  string
	RefreshToken string
}

type RefreshTokenOutput struct {
	AccessToken  string
	RefreshToken string
}
