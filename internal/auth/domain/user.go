package domain

import (
	"time"

	"github.com/google/uuid"
	"github.com/viniosilva/ipanemaboxapi/pkg"
	"gorm.io/gorm"
)

var (
	ErrUserNameEmpty = pkg.NewDomainError("userNameEmpty", "name is required")
)

type User struct {
	ID        uuid.UUID
	Name      string
	Email     Email
	Password  Password
	Phone     *Phone
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt
}

func NewUser(name string, email Email, password Password, phone *Phone) (*User, error) {
	now := time.Now()

	user := &User{
		ID:        uuid.New(),
		Name:      name,
		Email:     email,
		Password:  password,
		Phone:     phone,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := user.Validate(); err != nil {
		return nil, err
	}

	return user, nil
}

func (u *User) Validate() error {
	if u.Name == "" {
		return ErrUserNameEmpty
	}

	return nil
}

func (User) TableName() string {
	return "users"
}
