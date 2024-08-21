package presenter

const INTERNAL_SERVER_ERROR_MSG = "internal server error"

type ErrorRes struct {
	Message string `json:"message"`
}
