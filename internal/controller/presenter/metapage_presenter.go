package presenter

type MetadataPage struct {
	TotalCount  int `json:"total_count"`
	TotalPages  int `json:"total_pages"`
	CurrentPage int `json:"current_page"`
	PageSize    int `json:"page_size"`
}
