package dto

import (
	"time"

	"github.com/vinosilva/ipanemaboxapi/internal/model"
)

type CustomerCreateData struct {
	FullName string `validate:"required,lte=128"`
	Email    string `validate:"required,email,lte=128"`
}

type CustomerUpdateData struct {
	ID        int64     `validate:"gt=0"`
	FullName  string    `validate:"lte=128"`
	Email     string    `validate:"email,lte=128"`
	UpdatedAt time.Time `validate:"required"`
}

type CustomersResult struct {
	Data []model.Customer
}

type CustomerFindAllData struct {
	Page int `json:"page" validate:"gt=0"`
	Size int `json:"size" validate:"gt=0"`
}
