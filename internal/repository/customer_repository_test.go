package repository

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/viniosilva/ipanemaboxapi/internal/dto"
	"github.com/viniosilva/ipanemaboxapi/internal/model"
	"github.com/viniosilva/ipanemaboxapi/internal/utils/clock"
)

var fixedTime = time.Date(2024, time.May, 11, 18, 0, 0, 0, time.UTC)

func init() {
	clock.NowFunc = func() time.Time {
		return fixedTime
	}
}

func TestNewCustomerRepository(t *testing.T) {
	got := NewCustomerRepository(nil)

	assert.NotNil(t, got)
}

func TestCustomerRepository_Create(t *testing.T) {
	insertCustomerQuery := `INSERT INTO customers \(created_at, updated_at, name\) ` +
		`VALUES \(\$1, \$2, \$3\) ` +
		"RETURNING id"
	type args struct {
		ctx         context.Context
		customerDto dto.CustomerDataDto
	}
	tests := map[string]struct {
		mock    func(mock sqlmock.Sqlmock)
		args    args
		want    *model.Customer
		wantErr string
	}{
		"should create customer successfully": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPrepare(insertCustomerQuery).
					ExpectQuery().
					WithArgs(fixedTime, fixedTime, "Testing").
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
			},
			args: args{
				ctx:         context.TODO(),
				customerDto: dto.CustomerDataDto{Name: "Testing"},
			},
			want: &model.Customer{ID: 1, Name: "Testing"},
		},
		"should throw error on PrepareNamedContext": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPrepare(insertCustomerQuery).WillReturnError(fmt.Errorf("error"))
			},
			args: args{
				ctx:         context.TODO(),
				customerDto: dto.CustomerDataDto{Name: "Testing"},
			},
			wantErr: "error",
		},
		"should throw error on QueryRowContext": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPrepare(insertCustomerQuery).
					ExpectQuery().
					WillReturnError(fmt.Errorf("error"))
			},
			args: args{
				ctx:         context.TODO(),
				customerDto: dto.CustomerDataDto{Name: "Testing"},
			},
			wantErr: "error",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.mock(mock)

			repository := NewCustomerRepository(sqlx.NewDb(db, "postgres"))
			got, err := repository.Create(tt.args.ctx, tt.args.customerDto)

			mock.ExpectationsWereMet()
			assert.Equal(t, tt.want, got)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestCustomerRepository_Find(t *testing.T) {
	findCustomerQuery := "SELECT id, name " +
		"FROM customers " +
		`WHERE id = \$1 ` +
		"AND deleted_at IS NULL"
	type args struct {
		ctx context.Context
		id  int64
	}
	tests := map[string]struct {
		mock    func(mock sqlmock.Sqlmock)
		args    args
		want    *model.Customer
		wantErr string
	}{
		"should find customer successfully": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(findCustomerQuery).
					WithArgs(1).
					WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(1, "Testing"))
			},
			args: args{
				ctx: context.TODO(),
				id:  1,
			},
			want: &model.Customer{ID: 1, Name: "Testing"},
		},
		"should throw error when customer not found": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(findCustomerQuery).
					WithArgs(2).
					WillReturnError(sql.ErrNoRows)
			},
			args: args{
				ctx: context.TODO(),
				id:  2,
			},
			wantErr: "customer not found by ID 2",
		},
		"should throw error": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(findCustomerQuery).
					WithArgs(3).
					WillReturnError(fmt.Errorf("error"))
			},
			args: args{
				ctx: context.TODO(),
				id:  3,
			},
			wantErr: "error",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.mock(mock)

			repository := NewCustomerRepository(sqlx.NewDb(db, "postgres"))
			got, err := repository.Find(tt.args.ctx, tt.args.id)

			mock.ExpectationsWereMet()
			assert.Equal(t, tt.want, got)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestCustomerRepository_List(t *testing.T) {
	listCustomersQuery := "SELECT id, name " +
		"FROM customers " +
		"WHERE deleted_at IS NULL " +
		`LIMIT \$1 OFFSET \$2`

	countCustomersQuery := `SELECT COUNT\(\*\) ` +
		"FROM customers " +
		"WHERE deleted_at IS NULL"

	type args struct {
		ctx   context.Context
		page  int
		limit int
	}
	tests := map[string]struct {
		mock    func(mock sqlmock.Sqlmock)
		args    args
		want    *dto.CustomersList
		wantErr string
	}{
		"should list 2 of 2 customers successfully when page is 1 and limit is 10": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()

				rows := sqlmock.NewRows([]string{"id", "name"}).
					AddRow(1, "Customer 1").
					AddRow(2, "Customer 2")

				mock.ExpectQuery(listCustomersQuery).
					WithArgs(10, 0).
					WillReturnRows(rows)

				mock.ExpectQuery(countCustomersQuery).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

				mock.ExpectCommit()
			},
			args: args{
				ctx:   context.Background(),
				page:  1,
				limit: 10,
			},
			want: &dto.CustomersList{
				Meta: dto.MetadataPage{
					TotalCount:  2,
					TotalPages:  1,
					PageSize:    10,
					CurrentPage: 1,
				},
				Data: []model.Customer{
					{ID: 1, Name: "Customer 1"},
					{ID: 2, Name: "Customer 2"},
				},
			},
		},
		"should list 2 of 4 customers successfully when page is 2 and limit is 2": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()

				rows := sqlmock.NewRows([]string{"id", "name"}).
					AddRow(3, "Customer 3").
					AddRow(4, "Customer 4")

				mock.ExpectQuery(listCustomersQuery).
					WithArgs(2, 2).
					WillReturnRows(rows)

				mock.ExpectQuery(countCustomersQuery).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(4))

				mock.ExpectCommit()
			},
			args: args{
				ctx:   context.Background(),
				page:  2,
				limit: 2,
			},
			want: &dto.CustomersList{
				Meta: dto.MetadataPage{
					TotalCount:  4,
					TotalPages:  2,
					PageSize:    2,
					CurrentPage: 2,
				},
				Data: []model.Customer{
					{ID: 3, Name: "Customer 3"},
					{ID: 4, Name: "Customer 4"},
				},
			},
		},
		"should list empty customers list when page is 2 and pageSize is 10": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()

				mock.ExpectQuery(listCustomersQuery).
					WithArgs(10, 10).
					WillReturnRows(sqlmock.NewRows([]string{"id", "name"}))

				mock.ExpectQuery(countCustomersQuery).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

				mock.ExpectCommit()
			},
			args: args{
				ctx:   context.Background(),
				page:  2,
				limit: 10,
			},
			want: &dto.CustomersList{
				Meta: dto.MetadataPage{
					TotalCount:  0,
					TotalPages:  0,
					PageSize:    10,
					CurrentPage: 2,
				},
				Data: []model.Customer{},
			},
		},
		"should throw error when transaction begin returns error": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin().WillReturnError(fmt.Errorf("begin error"))
				mock.ExpectRollback()
			},
			args: args{
				ctx:   context.Background(),
				page:  1,
				limit: 10,
			},
			wantErr: "begin error",
		},
		"should throw error when query returns error": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()

				mock.ExpectQuery(listCustomersQuery).
					WillReturnError(fmt.Errorf("query error"))

				mock.ExpectRollback()
			},
			args: args{
				ctx:   context.Background(),
				page:  1,
				limit: 10,
			},
			wantErr: "query error",
		},
		"should throw error when query scan returns error": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()

				rows := sqlmock.NewRows([]string{"id", "name"}).
					AddRow("one", "Customer 1").
					AddRow("two", "Customer 2")

				mock.ExpectQuery(listCustomersQuery).
					WithArgs(10, 0).
					WillReturnRows(rows)

				mock.ExpectRollback()
			},
			args: args{
				ctx:   context.Background(),
				page:  1,
				limit: 10,
			},
			wantErr: "sql: Scan error on column index 0, name \"id\": converting driver.Value type string (\"one\") to a int64: invalid syntax",
		},
		"should throw error when count returns error": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()

				mock.ExpectQuery(listCustomersQuery).
					WithArgs(10, 0).
					WillReturnRows(sqlmock.NewRows([]string{"id", "name"}))

				mock.ExpectQuery(countCustomersQuery).
					WillReturnError(fmt.Errorf("count error"))

				mock.ExpectRollback()
			},
			args: args{
				ctx:   context.Background(),
				page:  1,
				limit: 10,
			},
			wantErr: "count error",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.mock(mock)

			repository := NewCustomerRepository(sqlx.NewDb(db, "postgres"))
			got, err := repository.List(tt.args.ctx, tt.args.page, tt.args.limit)

			mock.ExpectationsWereMet()
			assert.Equal(t, tt.want, got)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestCustomerRepository_Update(t *testing.T) {
	updateCustomerQuery := `UPDATE customers SET name = \$1, ` +
		`updated_at = \$2 ` +
		`WHERE id = \$3 ` +
		"AND deleted_at IS NULL " +
		"RETURNING id"
	type args struct {
		ctx         context.Context
		id          int64
		customerDto dto.CustomerDataDto
	}
	tests := map[string]struct {
		mock    func(mock sqlmock.Sqlmock)
		args    args
		want    *model.Customer
		wantErr string
	}{
		"should update customer successfully": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPrepare(updateCustomerQuery).
					ExpectQuery().
					WithArgs("Testing", fixedTime, 1).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
			},
			args: args{
				ctx: context.TODO(),
				id:  1,
				customerDto: dto.CustomerDataDto{
					Name: "Testing",
				},
			},
			want: &model.Customer{
				ID:   1,
				Name: "Testing",
			},
		},
		"should throw error when customer not found": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPrepare(updateCustomerQuery).
					ExpectQuery().
					WithArgs("Testing", fixedTime, 2).
					WillReturnError(sql.ErrNoRows)
			},
			args: args{
				ctx: context.TODO(),
				id:  2,
				customerDto: dto.CustomerDataDto{
					Name: "Testing",
				},
			},
			wantErr: "customer not found by ID 2",
		},
		"should throw error on PrepareContext": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPrepare(updateCustomerQuery).
					WillReturnError(fmt.Errorf("error"))
			},
			args: args{
				ctx: context.TODO(),
				id:  1,
				customerDto: dto.CustomerDataDto{
					Name: "Testing",
				},
			},
			wantErr: "error",
		},
		"should throw error on QueryRowContext": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectPrepare(updateCustomerQuery).
					ExpectQuery().
					WithArgs("Testing", fixedTime, 1).
					WillReturnError(fmt.Errorf("error"))
			},
			args: args{
				ctx: context.TODO(),
				id:  1,
				customerDto: dto.CustomerDataDto{
					Name: "Testing",
				},
			},
			wantErr: "error",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.mock(mock)

			repository := NewCustomerRepository(sqlx.NewDb(db, "postgres"))
			got, err := repository.Update(tt.args.ctx, tt.args.id, tt.args.customerDto)

			mock.ExpectationsWereMet()
			assert.Equal(t, tt.want, got)
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestCustomerRepository_Delete(t *testing.T) {
	deleteCustomerQuery := `UPDATE customers SET deleted_at = \$1 ` +
		`WHERE id = \$2 ` +
		"AND deleted_at IS NULL"
	type args struct {
		ctx context.Context
		id  int64
	}
	tests := map[string]struct {
		mock    func(mock sqlmock.Sqlmock)
		args    args
		wantErr string
	}{
		"should delete customer successfully": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(deleteCustomerQuery).
					WithArgs(fixedTime, 1).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			args: args{
				ctx: context.TODO(),
				id:  1,
			},
		},
		"should not throw error when customer not found": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(deleteCustomerQuery).
					WithArgs(fixedTime, 2).
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
			args: args{
				ctx: context.TODO(),
				id:  2,
			},
		},
		"should throw error on ExecContext": {
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(deleteCustomerQuery).
					WithArgs(fixedTime, 1).
					WillReturnError(fmt.Errorf("error"))
			},
			args: args{
				ctx: context.TODO(),
				id:  1,
			},
			wantErr: "error",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.mock(mock)

			repository := NewCustomerRepository(sqlx.NewDb(db, "postgres"))
			err = repository.Delete(tt.args.ctx, tt.args.id)

			mock.ExpectationsWereMet()
			if err != nil || tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}
