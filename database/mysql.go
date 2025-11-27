package database

import (
	"context"
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"time"
)

// MySqlDB structure
type MySqlDB struct {
	db *sql.DB
}

// Config MySQL configure
type Config struct {
	Username string
	Password string
	Host     string
	Port     int
	Database string
	Charset  string
}

// NewMySqlDB create MySQL database
func NewMySqlDB(cfg Config) (*MySqlDB, error) {
	// default charset
	charset := cfg.Charset
	if charset == "" {
		charset = "utf8mb4"
	}
	// DSN configure
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=True&loc=Local",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Database,
		charset,
	)
	// open MySQL database
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("error open database: %w", err)
	}
	// set connect pool parameters
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(time.Hour)
	// verify connect
	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("error verify connect: %w", err)
	}
	return &MySqlDB{db: db}, nil
}

// Close database connect
func (m *MySqlDB) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

// Ping database connection
func (m *MySqlDB) Ping(ctx context.Context) error {
	// ping context
	return m.db.PingContext(ctx)
}

// Exec perform execute(insert/query/delete)
func (m *MySqlDB) Exec(query string, args ...interface{}) (int64, error) {
	// perform execute
	result, err := m.db.Exec(query, args...)
	if err != nil {
		return 0, fmt.Errorf("error execute: %w", err)
	}
	// fetch rows affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("error fetch rows affected: %w", err)
	}
	return rowsAffected, nil
}

// Query query multiple rows
func (m *MySqlDB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	// perform query multiple rows
	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("error query: %w", err)
	}
	return rows, nil
}

// QueryRow query single row
func (m *MySqlDB) QueryRow(query string, args ...interface{}) *sql.Row {
	// perform query single row
	return m.db.QueryRow(query, args...)
}

// BeginTransaction begin transaction
func (m *MySqlDB) BeginTransaction() (*sql.Tx, error) {
	// perform begin transaction
	tx, err := m.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("error begin transaction: %w", err)
	}
	return tx, nil
}

// Prepare processing
func (m *MySqlDB) Prepare(query string) (*sql.Stmt, error) {
	stmt, err := m.db.Prepare(query)
	if err != nil {
		return nil, fmt.Errorf("error prepare: %w", err)
	}
	return stmt, nil
}
