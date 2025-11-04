package infrastructure

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type RedisTokenRepository struct {
	cache     *redis.Client
	keyPrefix string
}

func NewRedisTokenRepository(cache *redis.Client, keyPrefix string) *RedisTokenRepository {
	return &RedisTokenRepository{
		cache:     cache,
		keyPrefix: keyPrefix,
	}
}

func (r *RedisTokenRepository) SetTokenJWT(ctx context.Context, claims TokenJWTClaims, token string, ttl time.Duration) error {
	key := r.generateKey(claims)
	if err := r.cache.Set(ctx, key, token, ttl).Err(); err != nil {
		return fmt.Errorf("failed to set token: %w", err)
	}

	return nil
}

func (r *RedisTokenRepository) DeleteTokenJWT(ctx context.Context, userID uuid.UUID) error {
	key := r.generateKey(TokenJWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: userID.String(),
			ID:      "*",
		},
	})

	keys, err := r.cache.Keys(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to get keys: %w", err)
	} else if len(keys) == 0 {
		return ErrRegisterNotFound
	}

	if err := r.cache.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("failed to delete tokens: %w", err)
	}

	return nil
}

func (r *RedisTokenRepository) HasTokenJWT(ctx context.Context, claims TokenJWTClaims) (bool, error) {
	key := r.generateKey(claims)

	count, err := r.cache.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check if token exists: %w", err)
	}

	return count > 0, nil
}

func (r *RedisTokenRepository) generateKey(claims TokenJWTClaims) string {
	return fmt.Sprintf("%s:%s:%s", r.keyPrefix, claims.Subject, claims.ID)
}
