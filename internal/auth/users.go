package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound = errors.New("user not found")
	ErrUserExists   = errors.New("user already exists")
	ErrBadPassword  = errors.New("invalid password")
)

type User struct {
	ID        int64
	Username  string
	Email     string
	IsAdmin   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) Create(ctx context.Context, username, email, password string, isAdmin bool) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("username required")
	}
	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users(username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)`,
		username, nullStr(email), string(hash), boolInt(isAdmin),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrUserExists
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.Get(ctx, id)
}

func (s *Store) Get(ctx context.Context, id int64) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, username, COALESCE(email,''), is_admin, created_at, updated_at FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func (s *Store) GetByUsername(ctx context.Context, username string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, username, COALESCE(email,''), is_admin, created_at, updated_at FROM users WHERE username = ?`, username)
	return scanUser(row)
}

func (s *Store) Verify(ctx context.Context, username, password string) (*User, error) {
	var hash string
	row := s.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE username = ?`, username)
	if err := row.Scan(&hash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Spend the same bcrypt time as a real check so response timing
			// doesn't reveal which usernames exist.
			_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(password))
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return nil, ErrBadPassword
	}
	return s.GetByUsername(ctx, username)
}

// SetEmail updates the email column for the given user. An empty string
// clears the column (stored as NULL).
func (s *Store) SetEmail(ctx context.Context, id int64, email string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET email = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		nullStr(strings.TrimSpace(email)), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// SetAdmin changes the user's admin flag. Demoting an admin also signs them
// out everywhere (see revokeSessions), so apps that map roles at login pick up
// the change.
func (s *Store) SetAdmin(ctx context.Context, id int64, isAdmin bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var wasAdmin int
	if err := tx.QueryRowContext(ctx, `SELECT is_admin FROM users WHERE id = ?`, id).Scan(&wasAdmin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET is_admin = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		boolInt(isAdmin), id); err != nil {
		return err
	}
	if wasAdmin != 0 && !isAdmin {
		if err := revokeSessions(ctx, tx, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetPassword replaces the user's password and signs them out everywhere,
// so a reset actually locks out whoever had the old password.
func (s *Store) SetPassword(ctx context.Context, id int64, password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		string(hash), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrUserNotFound
	}
	if err := revokeSessions(ctx, tx, id); err != nil {
		return err
	}
	return tx.Commit()
}

// revokeSessions deletes every portal session and OIDC token held by the
// user. These tables belong to the portal and oidc packages, but they all
// hang off users(id), so the user store is the one place that sees every
// credential change.
func revokeSessions(ctx context.Context, tx *sql.Tx, id int64) error {
	for _, table := range []string{"portal_sessions", "oidc_access_tokens", "oidc_refresh_tokens"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE user_id = ?`, id); err != nil {
			return fmt.Errorf("revoke %s: %w", table, err)
		}
	}
	return nil
}

// dummyHash is compared against when a username doesn't exist, so Verify
// takes the same time either way.
var dummyHash = sync.OnceValue(func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("nass-timing-equaliser"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return h
})

func (s *Store) Delete(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *Store) List(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, username, COALESCE(email,''), is_admin, created_at, updated_at FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(r rowScanner) (*User, error) {
	var u User
	var admin int
	if err := r.Scan(&u.ID, &u.Username, &u.Email, &admin, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	u.IsAdmin = admin != 0
	return &u, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
