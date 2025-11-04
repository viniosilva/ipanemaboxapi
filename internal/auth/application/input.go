package application

import "github.com/google/uuid"

type RegisterInput struct {
	Name     string
	Email    string
	Password string
	Phone    *string
}

type LoginInput struct {
	Email    string
	Password string
}

type UpdateUserPasswordInput struct {
	UserID      uuid.UUID
	OldPassword string
	NewPassword string
}
