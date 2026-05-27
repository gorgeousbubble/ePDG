// Package store provides persistent session storage for ePDG.
// Supports SQLite (default) and MySQL backends.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"ePDG/config"
	"ePDG/database"
	"ePDG/logger"
	"ePDG/session"
)

// Store is the ePDG session persistence layer.
type Store struct {
	sqlite *database.SQLiteDB
	mysql  *database.MySqlDB
	dbType string
}

// New creates a new Store based on the database configuration.
func New(cfg config.DatabaseConfig) (*Store, error) {
	s := &Store{dbType: cfg.Type}
	switch cfg.Type {
	case "sqlite", "":
		path := cfg.SQLitePath
		if path == "" {
			path = "./data/epdg.db"
		}
		db, err := database.NewSQLiteDB(path)
		if err != nil {
			return nil, fmt.Errorf("store: sqlite: %w", err)
		}
		s.sqlite = db
		if err := s.initSQLiteSchema(); err != nil {
			return nil, fmt.Errorf("store: init schema: %w", err)
		}
	case "mysql":
		db, err := database.NewMySqlDB(database.Config{
			Host:     cfg.MySQL.Host,
			Port:     cfg.MySQL.Port,
			Username: cfg.MySQL.Username,
			Password: cfg.MySQL.Password,
			Database: cfg.MySQL.Database,
		})
		if err != nil {
			return nil, fmt.Errorf("store: mysql: %w", err)
		}
		s.mysql = db
		if err := s.initMySQLSchema(); err != nil {
			return nil, fmt.Errorf("store: init schema: %w", err)
		}
	default:
		return nil, fmt.Errorf("store: unknown database type %q", cfg.Type)
	}
	logger.Infof("Store: using %s database", cfg.Type)
	return s, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.sqlite != nil {
		return s.sqlite.Close()
	}
	if s.mysql != nil {
		return s.mysql.Close()
	}
	return nil
}

// ---- Schema ----

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    imsi            TEXT,
    msisdn          TEXT,
    apn             TEXT,
    state           INTEGER NOT NULL DEFAULT 0,
    assigned_ipv4   TEXT,
    assigned_ipv6   TEXT,
    local_teid      INTEGER,
    remote_teid     INTEGER,
    pgw_addr        TEXT,
    diameter_sid    TEXT,
    created_at      DATETIME NOT NULL,
    updated_at      DATETIME NOT NULL,
    expires_at      DATETIME
);
CREATE INDEX IF NOT EXISTS idx_sessions_imsi ON sessions(imsi);
CREATE INDEX IF NOT EXISTS idx_sessions_state ON sessions(state);
`

const mysqlSchema = `
CREATE TABLE IF NOT EXISTS sessions (
    id              VARCHAR(36) PRIMARY KEY,
    imsi            VARCHAR(20),
    msisdn          VARCHAR(20),
    apn             VARCHAR(100),
    state           INT NOT NULL DEFAULT 0,
    assigned_ipv4   VARCHAR(15),
    assigned_ipv6   VARCHAR(39),
    local_teid      INT UNSIGNED,
    remote_teid     INT UNSIGNED,
    pgw_addr        VARCHAR(50),
    diameter_sid    VARCHAR(200),
    created_at      DATETIME NOT NULL,
    updated_at      DATETIME NOT NULL,
    expires_at      DATETIME,
    INDEX idx_imsi (imsi),
    INDEX idx_state (state)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`

func (s *Store) initSQLiteSchema() error {
	_, err := s.sqlite.Exec(sqliteSchema)
	return err
}

func (s *Store) initMySQLSchema() error {
	_, err := s.mysql.Exec(mysqlSchema)
	return err
}

// ---- CRUD ----

// SaveSession persists a session to the database.
func (s *Store) SaveSession(ctx context.Context, sess *session.Session) error {
	var assignedIPv4, assignedIPv6, pgwAddr string
	if sess.AssignedIPv4 != nil {
		assignedIPv4 = sess.AssignedIPv4.String()
	}
	if sess.AssignedIPv6 != nil {
		assignedIPv6 = sess.AssignedIPv6.String()
	}
	if sess.PGWAddr != nil {
		pgwAddr = sess.PGWAddr.String()
	}

	query := `INSERT OR REPLACE INTO sessions
		(id, imsi, msisdn, apn, state, assigned_ipv4, assigned_ipv6,
		 local_teid, remote_teid, pgw_addr, diameter_sid, created_at, updated_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	if s.dbType == "mysql" {
		query = `INSERT INTO sessions
			(id, imsi, msisdn, apn, state, assigned_ipv4, assigned_ipv6,
			 local_teid, remote_teid, pgw_addr, diameter_sid, created_at, updated_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE
			imsi=VALUES(imsi), state=VALUES(state), assigned_ipv4=VALUES(assigned_ipv4),
			updated_at=VALUES(updated_at), expires_at=VALUES(expires_at)`
	}

	args := []interface{}{
		sess.ID, sess.IMSI, sess.MSISDN, sess.APN, int(sess.GetState()),
		assignedIPv4, assignedIPv6,
		sess.LocalTEID, sess.RemoteTEID, pgwAddr,
		sess.DiameterSessionID,
		sess.CreatedAt.UTC().Format(time.RFC3339),
		sess.UpdatedAt.UTC().Format(time.RFC3339),
		sess.SAExpiry.UTC().Format(time.RFC3339),
	}

	if s.sqlite != nil {
		_, err := s.sqlite.ExecContext(ctx, query, args...)
		return err
	}
	_, err := s.mysql.Exec(query, args...)
	return err
}

// DeleteSession removes a session from the database.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	query := "DELETE FROM sessions WHERE id = ?"
	if s.sqlite != nil {
		_, err := s.sqlite.ExecContext(ctx, query, id)
		return err
	}
	_, err := s.mysql.Exec(query, id)
	return err
}

// SessionRecord is a row from the sessions table.
type SessionRecord struct {
	ID           string
	IMSI         string
	MSISDN       string
	APN          string
	State        int
	AssignedIPv4 net.IP
	AssignedIPv6 net.IP
	LocalTEID    uint32
	RemoteTEID   uint32
	PGWAddr      string
	DiameterSID  string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ExpiresAt    time.Time
}

// GetSession retrieves a session record by ID.
func (s *Store) GetSession(ctx context.Context, id string) (*SessionRecord, error) {
	query := "SELECT id, imsi, msisdn, apn, state, assigned_ipv4, assigned_ipv6, local_teid, remote_teid, pgw_addr, diameter_sid, created_at, updated_at, expires_at FROM sessions WHERE id = ?"
	var row *sql.Row
	if s.sqlite != nil {
		row = s.sqlite.QueryRowContext(ctx, query, id)
	} else {
		row = s.mysql.QueryRow(query, id)
	}
	return scanSessionRecord(row)
}

// ListActiveSessions returns all sessions in non-terminal states.
func (s *Store) ListActiveSessions(ctx context.Context) ([]*SessionRecord, error) {
	query := fmt.Sprintf("SELECT id, imsi, msisdn, apn, state, assigned_ipv4, assigned_ipv6, local_teid, remote_teid, pgw_addr, diameter_sid, created_at, updated_at, expires_at FROM sessions WHERE state < %d", int(session.StateDisconnected))
	var rows *sql.Rows
	var err error
	if s.sqlite != nil {
		rows, err = s.sqlite.QueryContext(ctx, query)
	} else {
		rows, err = s.mysql.Query(query)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []*SessionRecord
	for rows.Next() {
		rec, err := scanSessionRow(rows)
		if err != nil {
			logger.Warnf("Store: scan session row: %v", err)
			continue
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

func scanSessionRecord(row *sql.Row) (*SessionRecord, error) {
	rec := &SessionRecord{}
	var ipv4Str, ipv6Str, expiresStr, createdStr, updatedStr string
	err := row.Scan(&rec.ID, &rec.IMSI, &rec.MSISDN, &rec.APN, &rec.State,
		&ipv4Str, &ipv6Str, &rec.LocalTEID, &rec.RemoteTEID, &rec.PGWAddr,
		&rec.DiameterSID, &createdStr, &updatedStr, &expiresStr)
	if err != nil {
		return nil, err
	}
	if ipv4Str != "" {
		rec.AssignedIPv4 = net.ParseIP(ipv4Str)
	}
	if ipv6Str != "" {
		rec.AssignedIPv6 = net.ParseIP(ipv6Str)
	}
	rec.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
	rec.UpdatedAt, _ = time.Parse(time.RFC3339, updatedStr)
	rec.ExpiresAt, _ = time.Parse(time.RFC3339, expiresStr)
	return rec, nil
}

func scanSessionRow(rows *sql.Rows) (*SessionRecord, error) {
	rec := &SessionRecord{}
	var ipv4Str, ipv6Str, expiresStr, createdStr, updatedStr string
	err := rows.Scan(&rec.ID, &rec.IMSI, &rec.MSISDN, &rec.APN, &rec.State,
		&ipv4Str, &ipv6Str, &rec.LocalTEID, &rec.RemoteTEID, &rec.PGWAddr,
		&rec.DiameterSID, &createdStr, &updatedStr, &expiresStr)
	if err != nil {
		return nil, err
	}
	if ipv4Str != "" {
		rec.AssignedIPv4 = net.ParseIP(ipv4Str)
	}
	if ipv6Str != "" {
		rec.AssignedIPv6 = net.ParseIP(ipv6Str)
	}
	rec.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
	rec.UpdatedAt, _ = time.Parse(time.RFC3339, updatedStr)
	rec.ExpiresAt, _ = time.Parse(time.RFC3339, expiresStr)
	return rec, nil
}
