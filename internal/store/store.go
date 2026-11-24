// Package store persists everything in a single SQLite file.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps separate read and write pools over one SQLite file.
type Store struct {
	W *sql.DB // single connection: serialises writes
	R *sql.DB // concurrent readers (WAL)
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	username TEXT NOT NULL UNIQUE COLLATE NOCASE,
	password_hash TEXT NOT NULL,
	active INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL,
	last_login INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	csrf TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domains (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	uname TEXT NOT NULL,
	suffix TEXT NOT NULL,
	note TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,

	monitor_enabled INTEGER NOT NULL DEFAULT 1,
	monitor_interval INTEGER NOT NULL DEFAULT 3600,

	catch_enabled INTEGER NOT NULL DEFAULT 0,
	catch_interval INTEGER NOT NULL DEFAULT 60,
	catch_start INTEGER NOT NULL DEFAULT 0,
	catch_end INTEGER NOT NULL DEFAULT 0,
	catch_duration INTEGER NOT NULL DEFAULT 10,
	catch_registrars TEXT NOT NULL DEFAULT '',
	auto_catch_pd INTEGER NOT NULL DEFAULT 0,

	notify_call INTEGER NOT NULL DEFAULT 0,
	notify_telegram INTEGER NOT NULL DEFAULT 0,

	status TEXT NOT NULL DEFAULT 'unknown',
	status_source TEXT NOT NULL DEFAULT '',
	status_since INTEGER NOT NULL DEFAULT 0,
	checked_at INTEGER NOT NULL DEFAULT 0,
	last_error TEXT NOT NULL DEFAULT '',
	error_streak INTEGER NOT NULL DEFAULT 0,

	info_source TEXT NOT NULL DEFAULT '',
	info_at INTEGER NOT NULL DEFAULT 0,
	registrar TEXT NOT NULL DEFAULT '',
	created INTEGER NOT NULL DEFAULT 0,
	expires INTEGER NOT NULL DEFAULT 0,
	updated INTEGER NOT NULL DEFAULT 0,
	available_date INTEGER NOT NULL DEFAULT 0,
	statuses TEXT NOT NULL DEFAULT '',
	nameservers TEXT NOT NULL DEFAULT '',
	pending_delete INTEGER NOT NULL DEFAULT 0,
	redemption INTEGER NOT NULL DEFAULT 0,
	whois_server TEXT NOT NULL DEFAULT '',
	raw_whois TEXT NOT NULL DEFAULT '',

	confirmed_avail_at INTEGER NOT NULL DEFAULT 0,
	confirm_tried_at INTEGER NOT NULL DEFAULT 0,
	confirm_detail TEXT NOT NULL DEFAULT '',

	catch_state TEXT NOT NULL DEFAULT 'idle',
	catch_started_at INTEGER NOT NULL DEFAULT 0,
	catch_deadline INTEGER NOT NULL DEFAULT 0,
	catch_ended_at INTEGER NOT NULL DEFAULT 0,
	catch_attempts INTEGER NOT NULL DEFAULT 0,
	catch_result TEXT NOT NULL DEFAULT '',
	catch_won_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS checks (
	id INTEGER PRIMARY KEY,
	domain_id INTEGER NOT NULL,
	ts INTEGER NOT NULL,
	purpose TEXT NOT NULL,
	source TEXT NOT NULL,
	result TEXT NOT NULL,
	ms INTEGER NOT NULL DEFAULT 0,
	detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_checks_domain ON checks(domain_id, id DESC);
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY,
	ts INTEGER NOT NULL,
	domain_id INTEGER NOT NULL DEFAULT 0,
	type TEXT NOT NULL,
	level TEXT NOT NULL DEFAULT 'info',
	detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain_id, id DESC);
CREATE TABLE IF NOT EXISTS orders (
	id INTEGER PRIMARY KEY,
	domain_id INTEGER NOT NULL,
	session_started INTEGER NOT NULL,
	ts INTEGER NOT NULL,
	registrar TEXT NOT NULL,
	attempt INTEGER NOT NULL,
	outcome TEXT NOT NULL,
	ms INTEGER NOT NULL DEFAULT 0,
	ref TEXT NOT NULL DEFAULT '',
	message TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_orders_domain ON orders(domain_id, id DESC);
CREATE TABLE IF NOT EXISTS source_health (
	suffix TEXT NOT NULL,
	source TEXT NOT NULL,
	ok INTEGER NOT NULL DEFAULT 0,
	errors INTEGER NOT NULL DEFAULT 0,
	streak INTEGER NOT NULL DEFAULT 0,
	last_ok INTEGER NOT NULL DEFAULT 0,
	last_err INTEGER NOT NULL DEFAULT 0,
	last_error TEXT NOT NULL DEFAULT '',
	cooldown_until INTEGER NOT NULL DEFAULT 0,
	unsupported_until INTEGER NOT NULL DEFAULT 0,
	avg_ms INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY(suffix, source)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS suffix_info (
	suffix TEXT PRIMARY KEY,
	source TEXT NOT NULL,
	fetched_at INTEGER NOT NULL,
	registrars TEXT NOT NULL DEFAULT '',
	prices TEXT NOT NULL DEFAULT '{}',
	error TEXT NOT NULL DEFAULT ''
);
`

// Open opens (and migrates) the database file.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(15000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	w, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	r, err := sql.Open("sqlite", dsn+"&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	r.SetMaxOpenConns(8)
	s := &Store{W: w, R: r}
	if _, err := w.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// migrate adds columns introduced after the initial schema.
func (s *Store) migrate() error {
	add := []struct{ table, col, def string }{
		{"domains", "fire_at", "INTEGER NOT NULL DEFAULT 0"},       // scheduled blind registration start (UTC)
		{"domains", "fire_lead", "INTEGER NOT NULL DEFAULT 10"},    // seconds before fire_at to start
		{"domains", "fire_duration", "INTEGER NOT NULL DEFAULT 5"}, // minutes of order attempts
		{"domains", "fire_auto", "INTEGER NOT NULL DEFAULT 1"},     // fire_at computed from the suffix release rule
		{"domains", "fire_done_at", "INTEGER NOT NULL DEFAULT 0"},  // fire_at value of the last executed fire
		{"domains", "snapshot_max", "INTEGER NOT NULL DEFAULT 0"},  // newest registry snapshot seen (RDAP)
		{"domains", "cand_status", "TEXT NOT NULL DEFAULT ''"},     // status change awaiting agreeing answers
		{"domains", "cand_count", "INTEGER NOT NULL DEFAULT 0"},
		{"domains", "cand_since", "INTEGER NOT NULL DEFAULT 0"}, // first answer showing the candidate (ms)
	}
	if _, err := s.W.Exec(`CREATE TABLE IF NOT EXISTS polls (
	id INTEGER PRIMARY KEY,
	domain_id INTEGER NOT NULL,
	start_ms INTEGER NOT NULL,
	end_ms INTEGER NOT NULL,
	purpose TEXT NOT NULL,
	source TEXT NOT NULL,
	via TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT '',
	verdict TEXT NOT NULL DEFAULT '',
	detail TEXT NOT NULL DEFAULT '',
	raw TEXT NOT NULL DEFAULT '',
	raw_ref INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_polls_domain ON polls(domain_id, id DESC);`); err != nil {
		return err
	}
	for _, a := range add {
		var n int
		if err := s.W.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`, a.table, a.col).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := s.W.Exec(`ALTER TABLE ` + a.table + ` ADD COLUMN ` + a.col + ` ` + a.def); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) Close() error {
	s.R.Close()
	return s.W.Close()
}

// Tx runs fn in a write transaction.
func (s *Store) Tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ---- helpers

func Unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func FromUnix(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

func JoinList(s []string) string { return strings.Join(s, ",") }

func SplitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---- settings

func (s *Store) GetSetting(key, def string) string {
	var v string
	if err := s.R.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v); err != nil {
		return def
	}
	return v
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.W.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) DeleteSetting(key string) { s.W.Exec(`DELETE FROM settings WHERE key=?`, key) }

// Prune deletes history older than the retention window.
func (s *Store) Prune(days int) {
	if days <= 0 {
		return
	}
	cut := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	s.W.Exec(`DELETE FROM checks WHERE ts<?`, cut)
	s.W.Exec(`DELETE FROM polls WHERE start_ms<?`, time.Now().Add(-time.Duration(min(days, 14))*24*time.Hour).UnixMilli())
	s.W.Exec(`DELETE FROM events WHERE ts<?`, cut)
	s.W.Exec(`DELETE FROM orders WHERE ts<?`, cut)
	s.W.Exec(`DELETE FROM sessions WHERE expires_at<?`, time.Now().Unix())
}
