package infrastructure

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type RedisTokenRepository struct {
	cache                      *redis.Client
	keyTokenJWTPrefix          string
	keyRefreshTokenPrefix      string
	keyUserRefreshTokensPrefix string
}

func NewRedisTokenRepository(cache *redis.Client, keyPrefix string) *RedisTokenRepository {
	return &RedisTokenRepository{
		cache:                      cache,
		keyTokenJWTPrefix:          fmt.Sprintf("%s:jwt", keyPrefix),
		keyRefreshTokenPrefix:      fmt.Sprintf("%s:refresh-token", keyPrefix),
		keyUserRefreshTokensPrefix: fmt.Sprintf("%s:user-refresh-tokens", keyPrefix),
	}
}

func (r *RedisTokenRepository) SetTokenJWT(ctx context.Context, claims TokenJWTClaims, token string, ttl time.Duration) error {
	key := r.generateTokenJWTKey(claims)
	if err := r.cache.Set(ctx, key, token, ttl).Err(); err != nil {
		return fmt.Errorf("failed to set token: %w", err)
	}

	return nil
}

func (r *RedisTokenRepository) DeleteTokenJWT(ctx context.Context, userID uuid.UUID) error {
	pattern := fmt.Sprintf("%s:%s:*", r.keyTokenJWTPrefix, userID.String())

	var keys []string
	iter := r.cache.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to scan keys: %w", err)
	}
	if len(keys) == 0 {
		return ErrRegisterNotFound
	}

	if err := r.cache.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("failed to delete tokens: %w", err)
	}

	return nil
}

func (r *RedisTokenRepository) HasTokenJWT(ctx context.Context, claims TokenJWTClaims) (bool, error) {
	key := r.generateTokenJWTKey(claims)

	count, err := r.cache.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check if token exists: %w", err)
	}

	return count > 0, nil
}

func (r *RedisTokenRepository) generateTokenJWTKey(claims TokenJWTClaims) string {
	return fmt.Sprintf("%s:%s:%s", r.keyTokenJWTPrefix, claims.Subject, claims.ID)
}

func (r *RedisTokenRepository) SetRefreshToken(ctx context.Context, refreshToken string, userID uuid.UUID, ttl time.Duration) error {
	key := r.generateRefreshTokenKey(refreshToken)
	pipe := r.cache.Pipeline()
	pipe.Set(ctx, key, userID.String(), ttl)
	pipe.SAdd(ctx, r.generateUserRefreshTokensKey(userID), refreshToken)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to set refresh token: %w", err)
	}

	return nil
}

func (r *RedisTokenRepository) GetUserIDByRefreshToken(ctx context.Context, refreshToken string) (uuid.UUID, error) {
	key := r.generateRefreshTokenKey(refreshToken)
	res, err := r.cache.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return uuid.UUID{}, ErrRegisterNotFound
		}

		return uuid.UUID{}, fmt.Errorf("failed to get user ID by refresh token: %w", err)
	}

	userID := uuid.MustParse(res)
	userRefreshTokensKey := r.generateUserRefreshTokensKey(userID)
	pipe := r.cache.Pipeline()
	pipe.Del(ctx, key)
	pipe.SRem(ctx, userRefreshTokensKey, refreshToken)
	if _, err := pipe.Exec(ctx); err != nil {
		return uuid.UUID{}, fmt.Errorf("failed to delete old refresh token: %w", err)
	}

	return userID, nil
}

func (r *RedisTokenRepository) DeleteRefreshToken(ctx context.Context, userID uuid.UUID, refreshToken string) error {
	refreshTokenKey := r.generateRefreshTokenKey(refreshToken)
	userRefreshTokensKey := r.generateUserRefreshTokensKey(userID)

	pipe := r.cache.Pipeline()
	pipe.Del(ctx, refreshTokenKey)
	pipe.SRem(ctx, userRefreshTokensKey, refreshToken)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}

func (r *RedisTokenRepository) DeleteUserRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	userRefreshTokensKey := r.generateUserRefreshTokensKey(userID)
	if err := r.cache.Del(ctx, userRefreshTokensKey).Err(); err != nil {
		if errors.Is(err, redis.Nil) {
			return ErrRegisterNotFound
		}

		return fmt.Errorf("failed to delete user refresh tokens: %w", err)
	}

	return nil
}

func (r *RedisTokenRepository) generateRefreshTokenKey(refreshToken string) string {
	return fmt.Sprintf("%s:%s", r.keyRefreshTokenPrefix, refreshToken)
}

func (r *RedisTokenRepository) generateUserRefreshTokensKey(userID uuid.UUID) string {
	return fmt.Sprintf("%s:%s", r.keyUserRefreshTokensPrefix, userID.String())
}
