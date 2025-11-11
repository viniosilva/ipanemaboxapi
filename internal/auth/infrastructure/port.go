package infrastructure

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type TokenRepository interface {
	SetTokenJWT(ctx context.Context, claims TokenJWTClaims, token string, ttl time.Duration) error
	DeleteTokenJWT(ctx context.Context, userID uuid.UUID) error
	HasTokenJWT(ctx context.Context, claims TokenJWTClaims) (bool, error)
	SetRefreshToken(ctx context.Context, refreshToken string, userID uuid.UUID, ttl time.Duration) error
	GetUserIDByRefreshToken(ctx context.Context, refreshToken string) (uuid.UUID, error)
	DeleteRefreshToken(ctx context.Context, userID uuid.UUID, refreshToken string) error
	DeleteUserRefreshTokens(ctx context.Context, userID uuid.UUID) error
}
