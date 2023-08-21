package presenter

type CustomerCreateRequest struct {
	FullName string `json:"fullname" example:"Mimoso Silva"`
	Email    string `json:"email" example:"mimoso@ipanemabox.com"`
}

type CustomerUpdateRequest struct {
	FullName  string `json:"fullname" example:"Mimoso Silva"`
	Email     string `json:"email" example:"mimoso@ipanemabox.com"`
	UpdatedAt string `json:"updated_at" example:"2000-12-31 23:59:59"`
}

type CustomersResponse struct {
	Data []CustomerResponseData `json:"data"`
}

type CustomerResponseData struct {
	ID        int64  `json:"id" example:"1"`
	CreatedAt string `json:"created_at" example:"2000-12-31 23:59:59"`
	UpdatedAt string `json:"updated_at" example:"2000-12-31 23:59:59"`
	FullName  string `json:"fullname" example:"Mimoso Silva"`
	Email     string `json:"email" example:"mimoso@ipanemabox.com"`
}
