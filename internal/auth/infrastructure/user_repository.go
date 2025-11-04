package infrastructure

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/domain"
	"gorm.io/gorm"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) CreateUser(ctx context.Context, user *domain.User) error {
	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (r *UserRepository) UpdateUser(ctx context.Context, user *domain.User) error {
	if err := r.db.WithContext(ctx).Save(user).Error; err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

func (r *UserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	conds := domain.User{ID: id}

	var user domain.User
	if err := r.db.WithContext(ctx).First(&user, conds).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("failed to get user by id: %w", ErrRegisterNotFound)
		}

		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}

	return &user, nil
}

func (r *UserRepository) GetUserByEmail(ctx context.Context, email domain.Email) (*domain.User, error) {
	conds := domain.User{Email: email}

	var user domain.User
	if err := r.db.WithContext(ctx).First(&user, conds).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("failed to get user by email: %w", ErrRegisterNotFound)
		}

		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

func (r *UserRepository) UserExistsByEmail(ctx context.Context, email domain.Email) (bool, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&domain.User{}).Where("email = ?", email).Count(&count).Error; err != nil {
		return false, fmt.Errorf("failed to check if user exists by email: %w", err)
	}

	return count > 0, nil
}
