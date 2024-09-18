package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"
	"github.com/viniosilva/ipanemaboxapi/internal/dto"
	"github.com/viniosilva/ipanemaboxapi/internal/exception"
	"github.com/viniosilva/ipanemaboxapi/internal/model"
	"github.com/viniosilva/ipanemaboxapi/internal/utils/clock"
)

type CustomerRepository struct {
	db *sqlx.DB
}

// New NewCustomerRepository instance a new customer repository
func NewCustomerRepository(db *sqlx.DB) *CustomerRepository {
	return &CustomerRepository{
		db: db,
	}
}

// Create a customer
func (r *CustomerRepository) Create(ctx context.Context, customerDto dto.CustomerDataDto) (*model.Customer, error) {
	customer := &model.Customer{Name: customerDto.Name}

	q := "INSERT INTO customers (created_at, updated_at, name) " +
		"VALUES ($1, $2, $3) " +
		"RETURNING id"

	stmt, err := r.db.PrepareContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	now := clock.Now()
	if err = stmt.QueryRowContext(ctx, now, now, customer.Name).Scan(&customer.ID); err != nil {
		return nil, err
	}

	return customer, nil
}

// Find a customer by ID
func (r *CustomerRepository) Find(ctx context.Context, id int64) (*model.Customer, error) {
	customer := &model.Customer{ID: id}

	q := "SELECT id, name " +
		"FROM customers " +
		"WHERE id = $1 " +
		"AND deleted_at IS NULL"

	err := r.db.GetContext(ctx, customer, q, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, exception.NewNotFoundException("customer not found by ID %d", id)
		}
		return nil, err
	}

	return customer, nil
}

func (r *CustomerRepository) List(ctx context.Context, page, limit int) (*dto.CustomersList, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	customersList := &dto.CustomersList{
		Data: []model.Customer{},
	}

	q := "SELECT id, name " +
		"FROM customers " +
		"WHERE deleted_at IS NULL " +
		"LIMIT $1 OFFSET $2"

	offset := (page - 1) * limit
	rows, err := tx.QueryContext(ctx, q, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		c := model.Customer{}
		if err = rows.Scan(&c.ID, &c.Name); err != nil {
			return nil, err
		}
		customersList.Data = append(customersList.Data, c)
	}

	qCount := "SELECT COUNT(*) " +
		"FROM customers " +
		"WHERE deleted_at IS NULL"
	if err = tx.QueryRowContext(ctx, qCount).Scan(&customersList.Meta.TotalCount); err != nil {
		return nil, err
	}

	customersList.Meta.CurrentPage = page
	customersList.Meta.PageSize = limit
	customersList.Meta.SetTotalPages()

	return customersList, nil
}

func (r *CustomerRepository) Update(ctx context.Context, id int64, customerDto dto.CustomerDataDto) (*model.Customer, error) {
	customer := &model.Customer{ID: id, Name: customerDto.Name}

	q := "UPDATE customers SET name = $1, " +
		"updated_at = $2 " +
		"WHERE id = $3 " +
		"AND deleted_at IS NULL " +
		"RETURNING id"

	stmt, err := r.db.PrepareContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	err = stmt.QueryRowContext(ctx, customer.Name, clock.Now(), customer.ID).Scan(&customer.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, exception.NewNotFoundException("customer not found by ID %d", id)
		}
		return nil, err
	}

	return customer, nil
}

func (r *CustomerRepository) Delete(ctx context.Context, id int64) error {
	q := "UPDATE customers SET deleted_at = $1 " +
		"WHERE id = $2 " +
		"AND deleted_at IS NULL"
	if _, err := r.db.ExecContext(ctx, q, clock.Now(), id); err != nil {
		return err
	}

	return nil
}
