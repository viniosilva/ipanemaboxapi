package presenter

type CustomerReq struct {
	Name string `json:"name" binding:"required"`
}

type CustomerRes struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}
