package infrastructure

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var ErrInvalidToken = errors.New("invalid token")

const (
	RefreshTokenLength = 64
)

type TokenService struct {
	tokenRepo             TokenRepository
	serviceName           string
	secretKey             []byte
	tokenJWTExpiresAt     time.Duration
	refreshTokenExpiresAt time.Duration
}

func NewTokenService(tokenRepo TokenRepository, serviceName, secretKey string, tokenJWTExpiresAt, refreshTokenExpiresAt time.Duration) *TokenService {
	return &TokenService{
		tokenRepo:             tokenRepo,
		serviceName:           serviceName,
		secretKey:             []byte(secretKey),
		tokenJWTExpiresAt:     tokenJWTExpiresAt,
		refreshTokenExpiresAt: refreshTokenExpiresAt,
	}
}

type TokenJWTClaims struct {
	jwt.RegisteredClaims
}

func (s *TokenService) GenerateTokenJWT(ctx context.Context, userID uuid.UUID) (string, error) {
	now := time.Now()

	claims := TokenJWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.tokenJWTExpiresAt)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.serviceName,
			Audience:  jwt.ClaimStrings{s.serviceName},
			Subject:   userID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", errors.Join(ErrInvalidToken, err)
	}

	if err = s.tokenRepo.SetTokenJWT(ctx, claims, tokenStr, s.tokenJWTExpiresAt); err != nil {
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

	if err := s.tokenRepo.DeleteUserRefreshTokens(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user refresh tokens: %w", err)
	}

	return nil
}

func (s *TokenService) GenerateRefreshToken(ctx context.Context, userID uuid.UUID) (string, error) {
	bytes := make([]byte, RefreshTokenLength/2) // divide by 2 because each byte is 2 characters in hex
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	refreshToken := hex.EncodeToString(bytes)
	if err := s.tokenRepo.SetRefreshToken(ctx, refreshToken, userID, s.refreshTokenExpiresAt); err != nil {
		return "", fmt.Errorf("failed to set refresh token: %w", err)
	}

	return refreshToken, nil
}

func (s *TokenService) GetRefreshTokenUserID(ctx context.Context, refreshToken string) (uuid.UUID, error) {
	return s.tokenRepo.GetUserIDByRefreshToken(ctx, refreshToken)
}
