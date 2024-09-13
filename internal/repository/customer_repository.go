package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"
	"github.com/viniosilva/ipanemaboxapi/internal/dto"
	"github.com/viniosilva/ipanemaboxapi/internal/exception"
	"github.com/viniosilva/ipanemaboxapi/internal/model"
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
func (r *CustomerRepository) Create(ctx context.Context, customerDto dto.CreateCustomerDto) (*model.Customer, error) {
	customer := &model.Customer{Name: customerDto.Name}

	q := "INSERT INTO customers (name) VALUES ($1) RETURNING id"
	stmt, err := r.db.PrepareContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	if err = stmt.QueryRowContext(ctx, customer.Name).Scan(&customer.ID); err != nil {
		return nil, err
	}

	return customer, nil
}

// Find a customer by ID
func (r *CustomerRepository) Find(ctx context.Context, id int64) (*model.Customer, error) {
	customer := &model.Customer{ID: id}

	q := "SELECT id, name FROM customers WHERE id = $1"
	err := r.db.GetContext(ctx, customer, q, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, exception.NewNotFoundException("customer not found by ID %d", id)
		}
		return nil, err
	}

	return customer, nil
}
