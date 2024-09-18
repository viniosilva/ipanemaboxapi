package dto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetadataPage_SetTotalPages(t *testing.T) {
	tests := map[string]struct {
		m    *MetadataPage
		want int
	}{
		"should set total page to 1 when totalCount is 10, currentPage is 1 and pageSize is 10": {
			m: &MetadataPage{
				TotalCount:  10,
				CurrentPage: 1,
				PageSize:    10,
			},
			want: 1,
		},
		"should set total page to 2 when totalCount is 11, currentPage is 1 and pageSize is 10": {
			m: &MetadataPage{
				TotalCount:  11,
				CurrentPage: 1,
				PageSize:    10,
			},
			want: 2,
		},
		"should set total page to 1 when totalCount is 5, currentPage is 1 and pageSize is 10": {
			m: &MetadataPage{
				TotalCount:  5,
				CurrentPage: 1,
				PageSize:    10,
			},
			want: 1,
		},
		"should set total page to 3 when totalCount is 25, currentPage is 1 and pageSize is 10": {
			m: &MetadataPage{
				TotalCount:  25,
				CurrentPage: 1,
				PageSize:    10,
			},
			want: 3,
		},
		"should set total page to 5 when totalCount is 45, currentPage is 1 and pageSize is 10": {
			m: &MetadataPage{
				TotalCount:  45,
				CurrentPage: 1,
				PageSize:    10,
			},
			want: 5,
		},
		"should set total page to 0 when totalCount is 0, currentPage is 1 and pageSize is 10": {
			m: &MetadataPage{
				TotalCount:  0,
				CurrentPage: 1,
				PageSize:    10,
			},
			want: 0,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tt.m.SetTotalPages()

			assert.Equal(t, tt.want, tt.m.TotalPages)
		})
	}
}
