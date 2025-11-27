package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"sync"
	"time"
)

// SQLiteDB SQLite3 database
type SQLiteDB struct {
	db   *sql.DB
	path string
	mu   sync.Mutex
}

// NewSQLiteDB create SQLite database
func NewSQLiteDB(dbPath string) (*SQLiteDB, error) {
	// create sqlite3 database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	// set pool parameters
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)
	// start test connect
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("database ping failed: %w", err)
	}
	// enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}
	return &SQLiteDB{
		db:   db,
		path: dbPath,
	}, nil
}

// Close SQLite3 database
func (s *SQLiteDB) Close() error {
	// sqlite3 database safe-lock
	s.mu.Lock()
	defer s.mu.Unlock()
	// close database
	if s.db != nil {
		err := s.db.Close()
		s.db = nil
		return err
	}
	return nil
}

// Exec perform non return SQL execute
func (s *SQLiteDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	return s.ExecContext(context.Background(), query, args...)
}

// ExecContext perform SQL execute
func (s *SQLiteDB) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	// sqlite3 database safe-lock
	s.mu.Lock()
	defer s.mu.Unlock()
	// check database connect
	if s.db == nil {
		return nil, errors.New("database not connected")
	}
	// perform execute
	return s.db.ExecContext(ctx, query, args...)
}

// Query perform query SQL
func (s *SQLiteDB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return s.QueryContext(context.Background(), query, args...)
}

// QueryContext perform query SQL with context
func (s *SQLiteDB) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	// sqlite3 database safe-lock
	s.mu.Lock()
	defer s.mu.Unlock()
	// check database connect
	if s.db == nil {
		return nil, errors.New("database not connected")
	}
	// perform query
	return s.db.QueryContext(ctx, query, args...)
}

// QueryRow perform query row SQL
func (s *SQLiteDB) QueryRow(query string, args ...interface{}) *sql.Row {
	return s.QueryRowContext(context.Background(), query, args...)
}

// QueryRowContext perform query row SQL with context
func (s *SQLiteDB) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	// sqlite3 database safe-lock
	s.mu.Lock()
	defer s.mu.Unlock()
	// check database connect
	if s.db == nil {
		return nil
	}
	// perform query row
	return s.db.QueryRowContext(ctx, query, args...)
}

// BeginTx begin transaction
func (s *SQLiteDB) BeginTx() (*sql.Tx, error) {
	return s.BeginTxContext(context.Background(), nil)
}

// BeginTxContext begin transaction with action
func (s *SQLiteDB) BeginTxContext(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	// sqlite3 database safe-lock
	s.mu.Lock()
	defer s.mu.Unlock()
	// check database connect
	if s.db == nil {
		return nil, errors.New("database not connected")
	}
	// perform begin transaction
	return s.db.BeginTx(ctx, opts)
}
