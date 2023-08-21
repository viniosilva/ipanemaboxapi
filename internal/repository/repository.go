package repository

type Repository struct{}

func (impl Repository) getLimitAndOffset(page, size int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if size <= 0 {
		size = 10
	}

	limit := size
	offset := (page - 1) * size

	return limit, offset
}
