package infrastructure

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/domain"
)

var ErrInvalidToken = errors.New("invalid token")

type TokenService struct {
	tokenRepo   TokenRepository
	serviceName string
	secretKey   []byte
	expiresAt   time.Duration
}

func NewTokenService(tokenRepo TokenRepository, serviceName, secretKey string, expiresAt time.Duration) *TokenService {
	return &TokenService{
		tokenRepo:   tokenRepo,
		serviceName: serviceName,
		secretKey:   []byte(secretKey),
		expiresAt:   expiresAt,
	}
}

type TokenJWTClaims struct {
	jwt.RegisteredClaims
}

func (s *TokenService) GenerateTokenJWT(ctx context.Context, user domain.User) (string, error) {
	now := time.Now()

	claims := TokenJWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.expiresAt)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.serviceName,
			Audience:  jwt.ClaimStrings{s.serviceName},
			Subject:   user.ID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", errors.Join(ErrInvalidToken, err)
	}

	if err = s.tokenRepo.SetTokenJWT(ctx, claims, tokenStr, s.expiresAt); err != nil {
		return "", err
	}

	return tokenStr, nil
}

func (s *TokenService) ValidateTokenJWT(ctx context.Context, tokenString string) (TokenJWTClaims, error) {
	claims := TokenJWTClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (any, error) {
		return s.secretKey, nil
	})
	if err != nil {
		return claims, errors.Join(ErrInvalidToken, err)
	}
	if !token.Valid {
		return claims, ErrInvalidToken
	}

	if exists, err := s.tokenRepo.HasTokenJWT(ctx, claims); err != nil {
		return claims, fmt.Errorf("failed to check if token exists: %w", err)
	} else if !exists {
		return claims, ErrInvalidToken
	}

	return claims, nil
}

func (s *TokenService) RevokeTokenJWT(ctx context.Context, userID uuid.UUID) error {
	if err := s.tokenRepo.DeleteTokenJWT(ctx, userID); err != nil && !errors.Is(err, ErrRegisterNotFound) {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	return nil
}
