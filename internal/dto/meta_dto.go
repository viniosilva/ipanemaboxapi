package dto

type Meta struct {
	TotalCount  int    `json:"total_count"`
	TotalPages  int    `json:"total_pages"`
	CurrentPage int    `json:"current_page"`
	PageSize    int    `json:"page_size"`
	Prev        string `json:"prev"`
	Next        string `json:"next"`
}
