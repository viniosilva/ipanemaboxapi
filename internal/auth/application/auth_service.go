package application

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/domain"
	"github.com/viniosilva/ipanemaboxapi/internal/auth/infrastructure"
	"github.com/viniosilva/ipanemaboxapi/pkg"
)

var (
	ErrUserAlreadyExists = pkg.NewDomainError("userAlreadyExists", "user already exists")
	ErrUserNotFound      = pkg.NewDomainError("userNotFound", "user not found")
)

type AuthServiceImpl struct {
	userRepo     UserRepository
	tokenService TokenService
}

func NewAuthService(userRepository UserRepository, tokenService TokenService) *AuthServiceImpl {
	return &AuthServiceImpl{
		userRepo:     userRepository,
		tokenService: tokenService,
	}
}

func (s *AuthServiceImpl) Register(ctx context.Context, input RegisterInput) (RegisterOutput, error) {
	email, err := domain.NewEmail(input.Email)
	if err != nil {
		return RegisterOutput{}, err
	}

	password, err := domain.NewPassword(input.Password)
	if err != nil {
		return RegisterOutput{}, err
	}

	var phone domain.Phone
	if p := input.Phone; p != nil {
		if phone, err = domain.NewPhone(*p); err != nil {
			return RegisterOutput{}, err
		}
	}

	user, err := domain.NewUser(input.Name, email, password, &phone)
	if err != nil {
		return RegisterOutput{}, err
	}

	userExists, err := s.userRepo.UserExistsByEmail(ctx, email)
	if err != nil {
		return RegisterOutput{}, err
	}
	if userExists {
		return RegisterOutput{}, ErrUserAlreadyExists
	}

	if err = s.userRepo.CreateUser(ctx, user); err != nil {
		return RegisterOutput{}, err
	}

	return RegisterOutput{
		ID:       user.ID,
		Name:     user.Name,
		Email:    user.Email,
		Password: user.Password,
		Phone:    user.Phone,
	}, nil
}

func (s *AuthServiceImpl) Login(ctx context.Context, input LoginInput) (LoginOutput, error) {
	if err := domain.ValidatePassword(input.Password); err != nil {
		if errors.Is(err, domain.ErrPasswordEmpty) {
			return LoginOutput{}, err
		}

		return LoginOutput{}, ErrUserNotFound
	}

	email, err := domain.NewEmail(input.Email)
	if err != nil {
		return LoginOutput{}, err
	}

	user, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, infrastructure.ErrRegisterNotFound) {
			return LoginOutput{}, ErrUserNotFound
		}

		return LoginOutput{}, err
	}

	if err = user.Password.Matches(input.Password); err != nil {
		return LoginOutput{}, ErrUserNotFound
	}

	token, err := s.tokenService.GenerateTokenJWT(ctx, *user)
	if err != nil {
		return LoginOutput{}, err
	}

	return LoginOutput{
		Token: token,
	}, nil
}

func (s *AuthServiceImpl) Logout(ctx context.Context, userID uuid.UUID) error {
	return s.tokenService.RevokeTokenJWT(ctx, userID)
}

func (s *AuthServiceImpl) UpdateUserPassword(ctx context.Context, input UpdateUserPasswordInput) error {
	if err := domain.ValidatePassword(input.NewPassword); err != nil {
		return err
	}

	user, err := s.userRepo.GetUserByID(ctx, input.UserID)
	if err != nil {
		if errors.Is(err, infrastructure.ErrRegisterNotFound) {
			return ErrUserNotFound
		}

		return err
	}

	if err = user.Password.Matches(input.OldPassword); err != nil {
		return err
	}

	user.Password, err = domain.NewPassword(input.NewPassword)
	if err != nil {
		return err
	}

	return s.userRepo.UpdateUser(ctx, user)
}
