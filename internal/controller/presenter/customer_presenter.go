package presenter

type CustomerReq struct {
	Name string `json:"name" binding:"required" example:"Fulano Oliveira"`
}

type CustomerRes struct {
	ID   int64  `json:"id" example:"1"`
	Name string `json:"name" example:"Fulano Oliveira"`
}

type CustomersListRes struct {
	Data     []CustomerRes `json:"data"`
	Metadata MetadataPage  `json:"metadata"`
}
