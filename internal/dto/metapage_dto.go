package dto

type MetadataPage struct {
	TotalCount  int
	TotalPages  int
	CurrentPage int
	PageSize    int
}

func (m *MetadataPage) SetTotalPages() {
	if m.PageSize > 0 {
		m.TotalPages = (m.TotalCount + m.PageSize - 1) / m.PageSize
	}
}
