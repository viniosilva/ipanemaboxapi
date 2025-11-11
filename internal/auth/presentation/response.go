package presentation

import "github.com/google/uuid"

type RegisterResponse struct {
	ID    uuid.UUID `json:"id" example:"123e4567-e89b-12d3-a456-426614174000"`
	Name  string    `json:"name" example:"John Doe"`
	Email string    `json:"email" example:"john.doe@example.com"`
	Phone *string   `json:"phone" example:"+5511999999999"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTY4MTIwMDB9.9PqE5VHqD7kz1jZlCwVjMZHhY0K8Jb5YQbHJ5yQ5Q"`
	RefreshToken string `json:"refresh_token" example:"123e4567e89b12d3a456426614174000"`
}

type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTY4MTIwMDB9.9PqE5VHqD7kz1jZlCwVjMZHhY0K8Jb5YQbHJ5yQ5Q"`
	RefreshToken string `json:"refresh_token" example:"123e4567e89b12d3a456426614174000"`
}
