package presenter

type ErrorResponse struct {
	Error    string   `json:"error" example:"Not Found"`
	Message  string   `json:"message,omitempty" example:"customer not found"`
	Messages []string `json:"messages,omitempty" example:"invalid field,invalid value"`
}
