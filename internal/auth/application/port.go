package application

import (
	"context"

	"github.com/google/uuid"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/domain"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/infrastructure"
)

type AuthService interface {
	Register(ctx context.Context, input RegisterInput) (RegisterOutput, error)
	Login(ctx context.Context, input LoginInput) (LoginOutput, error)
	Logout(ctx context.Context, userID uuid.UUID) error
	UpdateUserPassword(ctx context.Context, input UpdateUserPasswordInput) error
	RefreshToken(ctx context.Context, refreshToken string) (RefreshTokenOutput, error)
}

type UserRepository interface {
	CreateUser(ctx context.Context, user *domain.User) error
	UpdateUser(ctx context.Context, user *domain.User) error
	GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	GetUserByEmail(ctx context.Context, email domain.Email) (*domain.User, error)
	UserExistsByEmail(ctx context.Context, email domain.Email) (bool, error)
}

type TokenService interface {
	GenerateTokenJWT(ctx context.Context, userID uuid.UUID) (string, error)
	ValidateTokenJWT(ctx context.Context, tokenString string) (infrastructure.TokenJWTClaims, error)
	RevokeTokenJWT(ctx context.Context, userID uuid.UUID) error
	GenerateRefreshToken(ctx context.Context, userID uuid.UUID) (string, error)
	GetRefreshTokenUserID(ctx context.Context, refreshToken string) (uuid.UUID, error)
}
