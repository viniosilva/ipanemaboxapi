package dto

import "github.com/viniosilva/ipanemaboxapi/internal/model"

type CreateCustomerDto struct {
	Name string
}

type UpdateCustomerDto struct {
	Name string
}

type Customers struct {
	Data []model.Customer `json:"data"`
	Meta Meta             `json:"meta"`
}
