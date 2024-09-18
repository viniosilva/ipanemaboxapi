package dto

import "github.com/viniosilva/ipanemaboxapi/internal/model"

type CustomerDataDto struct {
	Name string
}

type CustomersList struct {
	Data []model.Customer
	Meta MetadataPage
}
